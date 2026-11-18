//! La sesión de sincronización del lado del teléfono: mantener viva una conexión
//! con un escritorio **ya pareado** y notar cuándo se cae.
//!
//! Es el paso que sigue al pareo: una vez fijada la huella de un escritorio, el
//! teléfono se reconecta a él (TLS mutuo, se verifica la huella fijada) y mantiene
//! la sesión con `Ping`/`Pong`. Sobre esta sesión viajarán después la batería y el
//! portapapeles; por ahora sólo sostiene el canal y reporta si está viva.
//!
//! Igual que el pareo, la lógica que decide es `vasak_connect_protocol::pure`
//! (pinning, `verify_hello`, `keepalive_exhausted`), y la sesión corre sobre
//! canales —una tarea lee, otra escribe— para que sea cancel-safe y probable con un
//! par en memoria, sin TLS. El establecimiento (`handshake`) y el bucle
//! (`run_loop`) están separados para que quien llama avise «conectado» recién
//! cuando la sesión quedó de verdad establecida, no antes.

use std::time::Duration;

use tokio::sync::mpsc;
use vasak_connect_protocol::pure::{
    evaluate_peer_cert, keepalive_exhausted, verify_hello, TrustDecision,
};
use vasak_connect_protocol::wire::{Message, PeerInfo};

use super::transport::SessionError;

/// Cada cuánto se manda un `Ping` para mantener viva la sesión y notar un corte que
/// el socket todavía no reportó. Igual que el daemon.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Cuántos `Ping` seguidos sin `Pong` se toleran antes de dar la sesión por caída.
const MAX_MISSED_PONGS: u32 = 2;

/// Tope para el `Hello` inicial: un escritorio que completa el TLS pero no se
/// presenta no puede dejar el `handshake` esperando para siempre (y con él el
/// comando `sync_connect`, que la interfaz usa para saber si reintentar).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Tope para un envío: el escritor escribe al socket sin plazo, así que si el par
/// deja de leer, la cola de salida se llena y el envío se cuelga. Con este tope, un
/// par que no lee se trata como caído en vez de trabar el bucle.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Por qué terminó la sesión de sincronización.
#[derive(Debug)]
pub enum SyncError {
    Session(SessionError),
    /// El `Hello` del escritorio no casa con el certificado TLS o la versión, o no
    /// llegó a tiempo.
    Handshake(String),
    /// El certificado del escritorio no es el que se fijó al parear: no es nuestro
    /// par de confianza (o rotó su identidad). No se sincroniza con él.
    NotTrusted,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Session(err) => write!(f, "{err}"),
            SyncError::Handshake(msg) => write!(f, "handshake: {msg}"),
            SyncError::NotTrusted => write!(f, "el escritorio no es el par fijado"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<SessionError> for SyncError {
    fn from(err: SessionError) -> Self {
        SyncError::Session(err)
    }
}

/// Establece la sesión: verifica que el certificado sea el fijado al parear
/// (pinning), presenta el teléfono y recibe el `Hello` del escritorio —con tope de
/// tiempo— validándolo. `Ok` significa sesión establecida y lista para el keepalive.
pub async fn handshake(
    peer_fingerprint: &str,
    pinned: &str,
    own: &PeerInfo,
    incoming: &mut mpsc::Receiver<Result<Message, SessionError>>,
    outgoing: &mpsc::Sender<Message>,
) -> Result<(), SyncError> {
    // El certificado tiene que ser el fijado al parear. Un par pareado que presenta
    // otra huella se rechaza (señal de suplantación o de identidad rotada).
    if evaluate_peer_cert(peer_fingerprint, Some(pinned)) != TrustDecision::Trusted {
        return Err(SyncError::NotTrusted);
    }

    send(outgoing, Message::Hello(own.clone())).await?;
    let their = match tokio::time::timeout(HANDSHAKE_TIMEOUT, recv(incoming)).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(SyncError::Handshake(
                "el escritorio no se presentó a tiempo".into(),
            ))
        }
    };
    match their {
        Message::Hello(info) => {
            verify_hello(&info, peer_fingerprint)
                .map_err(|e| SyncError::Handshake(e.to_string()))?;
        }
        other => {
            return Err(SyncError::Handshake(format!(
                "se esperaba Hello, llegó {other:?}"
            )))
        }
    }
    Ok(())
}

/// Mantiene viva la sesión ya establecida con `Ping`/`Pong`, hasta que el canal se
/// cierra o el keepalive se agota. `Ok` es un cierre ordinario (el par se fue o no
/// respondió).
pub async fn run_loop(
    incoming: &mut mpsc::Receiver<Result<Message, SessionError>>,
    outgoing: &mpsc::Sender<Message>,
) -> Result<(), SyncError> {
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // El primer tick es inmediato: se consume para que el primer `Ping` salga recién
    // al cumplirse el intervalo, no al arrancar.
    keepalive.tick().await;
    let mut missed_pongs: u32 = 0;

    loop {
        tokio::select! {
            entrante = incoming.recv() => {
                match entrante {
                    // Canal cerrado o error de sesión: cierre ordinario del bucle.
                    None | Some(Err(_)) => return Ok(()),
                    Some(Ok(Message::Pong)) => missed_pongs = 0,
                    Some(Ok(Message::Ping)) => send(outgoing, Message::Pong).await?,
                    // Otros mensajes (batería/portapapeles) llegan en PRs siguientes.
                    Some(Ok(_)) => {}
                }
            }
            _ = keepalive.tick() => {
                // Si el par no contestó los últimos `Ping`, se lo da por caído.
                if keepalive_exhausted(missed_pongs, MAX_MISSED_PONGS) {
                    return Ok(());
                }
                send(outgoing, Message::Ping).await?;
                missed_pongs += 1;
            }
        }
    }
}

/// Manda un mensaje con tope de tiempo. El escritor ya no está, o la cola llena por
/// un par que dejó de leer, se tratan igual: la sesión se cerró.
async fn send(outgoing: &mpsc::Sender<Message>, message: Message) -> Result<(), SyncError> {
    match tokio::time::timeout(SEND_TIMEOUT, outgoing.send(message)).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(SyncError::Session(SessionError::Closed)),
    }
}

async fn recv(
    incoming: &mut mpsc::Receiver<Result<Message, SessionError>>,
) -> Result<Message, SyncError> {
    incoming
        .recv()
        .await
        .ok_or(SyncError::Session(SessionError::Closed))?
        .map_err(SyncError::Session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vasak_connect_protocol::pure::device_id_from_fingerprint;
    use vasak_connect_protocol::wire::{DeviceKind, PROTOCOL_VERSION};

    fn info(fingerprint: &str) -> PeerInfo {
        PeerInfo {
            device_id: device_id_from_fingerprint(fingerprint),
            name: "Teléfono".to_string(),
            kind: DeviceKind::Phone,
            protocol_version: PROTOCOL_VERSION,
            fingerprint: fingerprint.to_string(),
        }
    }

    #[tokio::test]
    async fn una_huella_que_no_es_la_fijada_no_sincroniza() {
        let (_to, mut to_run_rx) = mpsc::channel::<Result<Message, SessionError>>(4);
        let (from_run_tx, _from) = mpsc::channel::<Message>(4);
        let err = handshake(
            "OTRA",
            "FIJADA",
            &info("PH:ON:E"),
            &mut to_run_rx,
            &from_run_tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SyncError::NotTrusted));
    }

    #[tokio::test]
    async fn el_handshake_valida_el_hello_del_escritorio() {
        let fp = "DE:SK";
        let (to_run_tx, mut to_run_rx) = mpsc::channel::<Result<Message, SessionError>>(4);
        let (from_run_tx, mut from_run_rx) = mpsc::channel::<Message>(4);
        to_run_tx.send(Ok(Message::Hello(info(fp)))).await.unwrap();

        handshake(fp, fp, &info("PH:ON:E"), &mut to_run_rx, &from_run_tx)
            .await
            .unwrap();
        // El teléfono se presentó.
        assert!(matches!(from_run_rx.recv().await, Some(Message::Hello(_))));
    }

    #[tokio::test]
    async fn un_primer_mensaje_que_no_es_hello_es_error_de_handshake() {
        let fp = "DE:SK";
        let (to_run_tx, mut to_run_rx) = mpsc::channel::<Result<Message, SessionError>>(4);
        let (from_run_tx, _from) = mpsc::channel::<Message>(4);
        to_run_tx.send(Ok(Message::Ping)).await.unwrap(); // no es Hello
        let err = handshake(fp, fp, &info("PH:ON:E"), &mut to_run_rx, &from_run_tx)
            .await
            .unwrap_err();
        assert!(matches!(err, SyncError::Handshake(_)));
    }

    #[tokio::test]
    async fn el_bucle_responde_el_ping_con_pong_y_cierra_al_cerrarse_el_canal() {
        let (to_run_tx, mut to_run_rx) = mpsc::channel::<Result<Message, SessionError>>(4);
        let (from_run_tx, mut from_run_rx) = mpsc::channel::<Message>(4);
        to_run_tx.send(Ok(Message::Ping)).await.unwrap();
        drop(to_run_tx); // cierra el canal → el bucle termina ordenado

        run_loop(&mut to_run_rx, &from_run_tx).await.unwrap();
        assert_eq!(from_run_rx.recv().await, Some(Message::Pong));
    }
}
