//! El pareo del lado del teléfono (el **iniciador**).
//!
//! El teléfono abre la sesión TLS, se presenta, y arranca el pareo con compromiso
//! (SAS/RFC-6189): se compromete a su clave DH efímera, el escritorio revela la
//! suya, el teléfono revela la propia, los dos derivan el mismo código corto (el
//! SAS) del secreto compartido, y el pareo se fija **sólo** cuando las dos
//! personas confirman que ven el mismo código.
//!
//! Nada de esto se decide acá: la máquina de estados, el compromiso y la
//! derivación del SAS son `vasak_connect_protocol::pure`, la MISMA que corre el
//! daemon. Este archivo sólo hace la parte que no es pura: el Diffie-Hellman
//! efímero (X25519, con `ring`), mover los mensajes por la sesión, mostrar el SAS
//! y esperar la confirmación —que puede llegar antes o después de la respuesta
//! del escritorio, y la máquina de estados ordena las dos—.

use ring::agreement;
use ring::rand::SystemRandom;
use tokio::sync::{mpsc, oneshot};
use vasak_connect_protocol::pure::{
    self, advance_pairing, derive_sas, device_id_from_fingerprint, sas_commitment, verify_hello,
    PairingEvent, PairingState,
};
use vasak_connect_protocol::wire::{Message, PeerInfo};

use super::store::PairedPeer;
use super::transport::{Session, SessionError};

/// Cómo terminó el pareo.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Fijado: las dos puntas confirmaron el SAS. Trae el par para persistir.
    Paired(PairedPeer),
    /// La persona de este lado rechazó el código.
    RejectedLocally,
    /// El escritorio rechazó, o canceló.
    RejectedByPeer,
    /// Se abortó: el compromiso no verificó (señal de intermediario) o el DH
    /// falló. Nunca se fija nada.
    Aborted,
}

/// Qué puede salir mal antes de llegar a un [`Outcome`].
#[derive(Debug)]
pub enum PairingError {
    Session(SessionError),
    /// El primer mensaje del escritorio no fue un `Hello` válido, o su `Hello` no
    /// casa con el certificado TLS / la versión del protocolo.
    Handshake(String),
    /// El generador del sistema no dio una clave DH efímera.
    Rng,
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairingError::Session(err) => write!(f, "{err}"),
            PairingError::Handshake(msg) => write!(f, "handshake: {msg}"),
            PairingError::Rng => write!(f, "no se pudo generar la clave efímera"),
        }
    }
}

impl std::error::Error for PairingError {}

impl From<SessionError> for PairingError {
    fn from(err: SessionError) -> Self {
        PairingError::Session(err)
    }
}

/// Genera un par DH efímero X25519: la clave privada y su pública en bytes
/// crudos. `None` si el generador del sistema falla.
fn generate_ephemeral() -> Option<(agreement::EphemeralPrivateKey, Vec<u8>)> {
    let rng = SystemRandom::new();
    let secret = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).ok()?;
    let public = secret.compute_public_key().ok()?;
    Some((secret, public.as_ref().to_vec()))
}

/// Computa el secreto compartido X25519 con la clave privada propia (que se
/// consume) y la pública del par. `None` si la pública del par es inválida.
fn compute_shared(secret: agreement::EphemeralPrivateKey, peer_public: &[u8]) -> Option<Vec<u8>> {
    agreement::agree_ephemeral(
        secret,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public),
        |shared| shared.to_vec(),
    )
    .ok()
}

/// Corre el pareo completo sobre una sesión ya conectada.
///
/// `own` es lo que el teléfono dice de sí mismo; `sas_tx` recibe el código a
/// mostrarle a la persona; `confirm_rx` trae su decisión (aceptar/rechazar), que
/// puede llegar antes o después de la respuesta del escritorio.
pub async fn run(
    session: &mut Session,
    own: &PeerInfo,
    sas_tx: mpsc::UnboundedSender<String>,
    confirm_rx: oneshot::Receiver<bool>,
) -> Result<Outcome, PairingError> {
    let own_fingerprint = own.fingerprint.clone();
    let peer_fingerprint = session.peer_fingerprint().to_string();

    // 1. Presentarse y recibir la presentación del escritorio, validándola contra
    //    el certificado TLS y la versión del protocolo.
    session.write(&Message::Hello(own.clone())).await?;
    let their_info = match session.read().await? {
        Message::Hello(info) => info,
        other => {
            return Err(PairingError::Handshake(format!(
                "se esperaba Hello, llegó {other:?}"
            )))
        }
    };
    verify_hello(&their_info, &peer_fingerprint)
        .map_err(|err| PairingError::Handshake(err.to_string()))?;

    // 2. Iniciar: generar la clave efímera, comprometerse a ella y mandar el
    //    PairRequest.
    let (secret, own_public) = generate_ephemeral().ok_or(PairingError::Rng)?;
    let mut secret = Some(secret);
    let commitment = sas_commitment(&own_public);
    let mut state = PairingState::Idle;
    let action = advance_pairing(&state, PairingEvent::LocalInitiate { commitment });
    state = action.next;
    if let Some(message) = action.send {
        session.write(&message).await?;
    }

    // 3. Manejar, en el orden que lleguen, la revelación DH y la respuesta del
    //    escritorio por un lado, y la confirmación local por el otro.
    let mut confirm_rx = Some(confirm_rx);
    loop {
        let action = tokio::select! {
            incoming = session.read() => {
                match incoming? {
                    Message::PairDh { dh_pub } => {
                        on_peer_dh(&state, &dh_pub, &mut secret, &own_public, &own_fingerprint, &peer_fingerprint)?
                    }
                    Message::PairResponse { accepted } => {
                        advance_pairing(&state, PairingEvent::PeerResponse { accepted })
                    }
                    // Cualquier otro mensaje en medio del pareo se ignora.
                    _ => continue,
                }
            }
            confirm = async { confirm_rx.as_mut().unwrap().await }, if confirm_rx.is_some() => {
                confirm_rx = None;
                // Si el canal de confirmación se cerró sin respuesta, se trata como
                // un rechazo: no se fija nada sin un sí explícito.
                let accept = confirm.unwrap_or(false);
                advance_pairing(&state, PairingEvent::LocalConfirm { accept })
            }
        };

        state = action.next.clone();
        if let Some(message) = action.send {
            session.write(&message).await?;
        }
        if let Some(code) = action.notify_code {
            // Si nadie escucha el SAS (la pantalla se fue), no es fatal acá.
            let _ = sas_tx.send(code);
        }
        if action.abort {
            return Ok(Outcome::Aborted);
        }
        if action.pin {
            return Ok(Outcome::Paired(paired_from(&peer_fingerprint, &their_info)));
        }
        // Volver a reposo sin fijar (y sin abortar) es una cancelación: la decidió
        // esta persona o el escritorio, según quién dijo que no.
        if matches!(state, PairingState::Idle) {
            return Ok(if confirm_rx.is_none() {
                Outcome::RejectedLocally
            } else {
                Outcome::RejectedByPeer
            });
        }
    }
}

/// El paso al recibir el `PairDh` del escritorio: computa el secreto compartido
/// con nuestra clave, deriva el SAS en el orden canónico (iniciador primero) y
/// hace avanzar la máquina revelando nuestra clave. Si el DH falla, aborta.
fn on_peer_dh(
    state: &PairingState,
    peer_dh_hex: &str,
    secret: &mut Option<agreement::EphemeralPrivateKey>,
    own_public: &[u8],
    own_fingerprint: &str,
    peer_fingerprint: &str,
) -> Result<pure::PairingAction, PairingError> {
    let Some(peer_public) = hex::decode(peer_dh_hex).ok() else {
        return Ok(aborted(state));
    };
    // `take`: la clave efímera se consume en el acuerdo, exista o no el resultado.
    let Some(secret) = secret.take() else {
        return Ok(aborted(state));
    };
    let Some(shared) = compute_shared(secret, &peer_public) else {
        return Ok(aborted(state));
    };
    // Iniciador: nuestra clave es la del iniciador, la del par la del respondedor.
    let sas = derive_sas(
        &shared,
        own_public,
        &peer_public,
        own_fingerprint,
        peer_fingerprint,
    );
    Ok(advance_pairing(
        state,
        PairingEvent::PeerDh {
            reveal: hex::encode(own_public),
            sas,
        },
    ))
}

/// Arma el par a persistir **desde la huella autenticada**, no del `Hello`.
///
/// El `device_id` se deriva de la huella del certificado TLS —lo único que el
/// handshake y el pinning garantizan—, no del `device_id` que el escritorio
/// declara en su `Hello`, que no está autenticado (`verify_hello` liga sólo la
/// huella y la versión). Si se tomara del `Hello`, un escritorio malicioso podría
/// declarar el `device_id` de uno ya pareado y, como el almacén deduplica por
/// `device_id`, expulsar su huella fijada tras un pareo confirmado. Derivándolo de
/// la huella, la clave del almacén queda 1:1 con la huella y no se puede colisionar.
/// El `name` del `Hello` se guarda sólo como texto para mostrar.
fn paired_from(peer_fingerprint: &str, their_info: &PeerInfo) -> PairedPeer {
    PairedPeer {
        device_id: device_id_from_fingerprint(peer_fingerprint),
        name: their_info.name.clone(),
        kind: their_info.kind,
        fingerprint: peer_fingerprint.to_string(),
    }
}

/// Una acción terminal de aborto, para cuando el DH falla: vuelve a reposo y pide
/// cerrar, sin fijar nada.
fn aborted(state: &PairingState) -> pure::PairingAction {
    let _ = state;
    pure::PairingAction {
        next: PairingState::Idle,
        send: None,
        pin: false,
        notify_code: None,
        abort: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vasak_connect_protocol::wire::{DeviceKind, PROTOCOL_VERSION};

    /// El par que se persiste saca su `device_id` de la huella del certificado
    /// (autenticada), NO del `Hello` del escritorio. Si no, un escritorio
    /// malicioso que declara el `device_id` de uno ya pareado expulsaría su huella
    /// fijada (el almacén deduplica por `device_id`). Es el fix de H1 del review.
    #[test]
    fn el_par_guardado_usa_el_device_id_de_la_huella_no_el_del_hello() {
        let their = PeerInfo {
            // Lo que el escritorio DICE ser: el device_id de otro, ya pareado.
            device_id: "id-de-otro-ya-pareado".to_string(),
            name: "Escritorio de Joaco".to_string(),
            kind: DeviceKind::Desktop,
            protocol_version: PROTOCOL_VERSION,
            fingerprint: "huella-que-el-par-declara".to_string(),
        };
        let fingerprint = "AA:BB:CC:DD";

        let paired = paired_from(fingerprint, &their);
        assert_eq!(paired.fingerprint, fingerprint);
        // La clave del almacén sale de la huella, no del Hello.
        assert_eq!(paired.device_id, device_id_from_fingerprint(fingerprint));
        assert_ne!(paired.device_id, "id-de-otro-ya-pareado");
        // El nombre sí se toma del Hello (sólo para mostrar).
        assert_eq!(paired.name, "Escritorio de Joaco");
    }

    /// Las dos puntas derivan el MISMO SAS del mismo DH, en el orden canónico
    /// (iniciador primero). Es la interoperabilidad con el daemon: si esto fallara,
    /// las pantallas mostrarían códigos distintos y nadie podría parear.
    #[test]
    fn iniciador_y_respondedor_derivan_el_mismo_sas() {
        // Iniciador A, respondedor B.
        let (a_sec, a_pub) = generate_ephemeral().unwrap();
        let (b_sec, b_pub) = generate_ephemeral().unwrap();

        let a_shared = compute_shared(a_sec, &b_pub).unwrap();
        let b_shared = compute_shared(b_sec, &a_pub).unwrap();
        assert_eq!(a_shared, b_shared, "el secreto DH tiene que coincidir");

        let fp_a = "AA:AA";
        let fp_b = "BB:BB";
        // El iniciador deriva con su clave primero; el respondedor, con la del
        // iniciador (A) primero también: el orden es canónico, no «el mío primero».
        let sas_a = derive_sas(&a_shared, &a_pub, &b_pub, fp_a, fp_b);
        let sas_b = derive_sas(&b_shared, &a_pub, &b_pub, fp_a, fp_b);
        assert_eq!(sas_a, sas_b);
        assert_eq!(sas_a.len(), 6);
        assert!(sas_a.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn dos_pareos_distintos_dan_claves_distintas() {
        let (_, a1) = generate_ephemeral().unwrap();
        let (_, a2) = generate_ephemeral().unwrap();
        assert_ne!(a1, a2, "cada pareo usa una clave efímera nueva");
    }

    #[test]
    fn un_dh_del_par_invalido_aborta_sin_fijar() {
        let (secret, own_public) = generate_ephemeral().unwrap();
        let mut secret = Some(secret);
        // «zz» no es hex: el acuerdo no puede computarse.
        let action = on_peer_dh(
            &PairingState::OutgoingCommitted,
            "zz",
            &mut secret,
            &own_public,
            "AA",
            "BB",
        )
        .unwrap();
        assert!(action.abort);
        assert!(!action.pin);
    }
}
