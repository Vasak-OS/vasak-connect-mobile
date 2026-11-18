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
    accept_incoming_clipboard, evaluate_peer_cert, keepalive_exhausted, verify_hello, TrustDecision,
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

/// Cada cuánto se mira el portapapeles propio para ver si cambió. El teléfono no
/// recibe un aviso cuando el usuario copia algo —a diferencia del escritorio, que
/// escucha a Wayland—, así que se sondea. Dos segundos es el mismo ritmo que usa
/// KDE Connect: se nota inmediato sin consultar el portapapeles a cada rato.
const CLIPBOARD_POLL: Duration = Duration::from_secs(2);

/// El portapapeles del aparato, detrás de un trait para que el bucle sea probable
/// sin Tauri: los tests pasan un doble en memoria y `commands.rs` pasa un impl real
/// que envuelve el plugin con el `AppHandle`. `read` devuelve `None` si está vacío
/// o no se pudo leer; `write` es de mejor esfuerzo (un fallo al escribir no cae la
/// sesión).
pub trait Clipboard {
    fn read(&self) -> Option<String>;
    /// Devuelve si el texto quedó de verdad en el portapapeles (`false` si la
    /// escritura falló), para no marcar como sincronizado algo que no se escribió:
    /// si no, el próximo sondeo rebotaría el valor viejo.
    fn write(&self, text: &str) -> bool;
}

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

/// Mantiene viva la sesión ya establecida con `Ping`/`Pong` y sincroniza el
/// portapapeles en las dos direcciones, hasta que el canal se cierra o el keepalive
/// se agota. `Ok` es un cierre ordinario (el par se fue o no respondió).
///
/// El portapapeles va detrás del trait [`Clipboard`]: al recibir `Clipboard{text}`
/// de un par pareado se escribe localmente, y cada [`CLIPBOARD_POLL`] se mira el
/// propio y, si cambió, se empuja al escritorio. `last_synced` guarda lo último
/// sincronizado en cualquier dirección y es el anti-eco: no se reenvía lo recién
/// recibido ni lo que no cambió. Arranca con lo que ya hay copiado, para no empujar
/// el portapapeles entero al conectar.
pub async fn run_loop(
    incoming: &mut mpsc::Receiver<Result<Message, SessionError>>,
    outgoing: &mpsc::Sender<Message>,
    clipboard: &impl Clipboard,
) -> Result<(), SyncError> {
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // El primer tick es inmediato: se consume para que el primer `Ping` salga recién
    // al cumplirse el intervalo, no al arrancar.
    keepalive.tick().await;
    let mut missed_pongs: u32 = 0;

    let mut clipboard_poll = tokio::time::interval(CLIPBOARD_POLL);
    clipboard_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    clipboard_poll.tick().await; // el inmediato se consume, igual que el keepalive
    let mut last_synced: Option<String> = clipboard.read();

    loop {
        tokio::select! {
            entrante = incoming.recv() => {
                match entrante {
                    // Canal cerrado o error de sesión: cierre ordinario del bucle.
                    None | Some(Err(_)) => return Ok(()),
                    Some(Ok(Message::Pong)) => missed_pongs = 0,
                    Some(Ok(Message::Ping)) => send(outgoing, Message::Pong).await?,
                    Some(Ok(Message::Clipboard { text })) => {
                        // Sólo de un par pareado (acá siempre lo es: el handshake ya
                        // fijó la huella) y no vacío. Se escribe y se marca como
                        // sincronizado para que el próximo sondeo no lo rebote.
                        if let Some(text) = accept_incoming_clipboard(true, text) {
                            // Sólo se marca como sincronizado si la escritura pegó:
                            // si falla, el valor viejo sigue en el portapapeles y no
                            // hay que rebotarlo en el próximo sondeo.
                            if clipboard.write(&text) {
                                last_synced = Some(text);
                            }
                        }
                    }
                    // Otros mensajes (batería) llegan en PRs siguientes.
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
            _ = clipboard_poll.tick() => {
                // Si el portapapeles propio cambió respecto de lo último
                // sincronizado y no está vacío, se empuja al escritorio.
                if let Some(text) = clipboard.read() {
                    if !text.is_empty() && last_synced.as_deref() != Some(text.as_str()) {
                        send(outgoing, Message::Clipboard { text: text.clone() }).await?;
                        last_synced = Some(text);
                    }
                }
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

    /// Portapapeles de mentira para probar el bucle sin Tauri. `read` devuelve lo
    /// que `write` dejó (o lo precargado); el bucle lo recibe por referencia
    /// compartida, así el test ve lo que escribió y puede simular un cambio local.
    #[derive(Default)]
    struct FakeClipboard {
        contenido: std::sync::Mutex<Option<String>>,
        /// Si es `true`, `write` falla y no toca el contenido.
        escritura_falla: bool,
    }

    impl FakeClipboard {
        fn con(texto: &str) -> Self {
            FakeClipboard {
                contenido: std::sync::Mutex::new(Some(texto.to_string())),
                escritura_falla: false,
            }
        }
        fn que_no_escribe(texto: &str) -> Self {
            FakeClipboard {
                escritura_falla: true,
                ..Self::con(texto)
            }
        }
        fn set(&self, texto: &str) {
            *self.contenido.lock().unwrap() = Some(texto.to_string());
        }
    }

    impl Clipboard for FakeClipboard {
        fn read(&self) -> Option<String> {
            self.contenido.lock().unwrap().clone()
        }
        fn write(&self, text: &str) -> bool {
            if self.escritura_falla {
                return false;
            }
            *self.contenido.lock().unwrap() = Some(text.to_string());
            true
        }
    }

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

        run_loop(&mut to_run_rx, &from_run_tx, &FakeClipboard::default())
            .await
            .unwrap();
        assert_eq!(from_run_rx.recv().await, Some(Message::Pong));
    }

    /// Corre el bucle con un guion: `guion` recibe el emisor entrante y el
    /// portapapeles, y al terminar suelta el emisor (cierra el canal). Devuelve lo
    /// que el bucle mandó, sin los `Ping` del keepalive. El reloj va pausado: los
    /// `sleep` del guion lo adelantan solos y disparan el sondeo de forma
    /// determinista.
    async fn correr<F, Fut>(clip: &FakeClipboard, guion: F) -> Vec<Message>
    where
        F: FnOnce(mpsc::Sender<Result<Message, SessionError>>) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let (to_run_tx, mut to_run_rx) = mpsc::channel::<Result<Message, SessionError>>(8);
        let (from_run_tx, mut from_run_rx) = mpsc::channel::<Message>(8);
        let (resultado, ()) = tokio::join!(
            run_loop(&mut to_run_rx, &from_run_tx, clip),
            guion(to_run_tx)
        );
        resultado.unwrap();
        drop(from_run_tx);
        let mut salida = Vec::new();
        while let Some(m) = from_run_rx.recv().await {
            if m != Message::Ping {
                salida.push(m);
            }
        }
        salida
    }

    fn clip_msg(text: &str) -> Message {
        Message::Clipboard {
            text: text.to_string(),
        }
    }

    const UN_SONDEO: Duration = Duration::from_millis(2100);

    #[tokio::test(start_paused = true)]
    async fn lo_que_llega_se_escribe_y_no_se_rebota() {
        let clip = FakeClipboard::default();
        let salida = correr(&clip, |tx| async move {
            tx.send(Ok(clip_msg("desde el escritorio"))).await.unwrap();
            tokio::time::sleep(UN_SONDEO).await; // pasa un sondeo
        })
        .await;
        assert_eq!(clip.read().as_deref(), Some("desde el escritorio"));
        assert!(salida.is_empty(), "no debe rebotar: {salida:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn un_cambio_local_se_empuja_al_escritorio() {
        let clip = FakeClipboard::con("viejo");
        let c = &clip;
        let salida = correr(&clip, |tx| async move {
            c.set("copiado en el teléfono");
            tokio::time::sleep(UN_SONDEO).await;
            drop(tx);
        })
        .await;
        assert_eq!(salida, vec![clip_msg("copiado en el teléfono")]);
    }

    #[tokio::test(start_paused = true)]
    async fn un_portapapeles_vacio_recibido_no_se_escribe() {
        let clip = FakeClipboard::con("intacto");
        let salida = correr(&clip, |tx| async move {
            tx.send(Ok(clip_msg(""))).await.unwrap();
            tokio::time::sleep(UN_SONDEO).await;
        })
        .await;
        assert_eq!(clip.read().as_deref(), Some("intacto"));
        assert!(salida.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn lo_que_no_cambio_no_se_reenvia() {
        // Lo ya copiado al conectar no se empuja, ni en el primer sondeo ni en
        // los siguientes.
        let clip = FakeClipboard::con("ya estaba");
        let salida = correr(&clip, |tx| async move {
            tokio::time::sleep(UN_SONDEO * 3).await;
            drop(tx);
        })
        .await;
        assert!(salida.is_empty(), "{salida:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn un_cambio_local_se_empuja_una_sola_vez() {
        let clip = FakeClipboard::default();
        let c = &clip;
        let salida = correr(&clip, |tx| async move {
            c.set("uno");
            tokio::time::sleep(UN_SONDEO * 3).await; // varios sondeos, un solo envío
            drop(tx);
        })
        .await;
        assert_eq!(salida, vec![clip_msg("uno")]);
    }

    #[tokio::test(start_paused = true)]
    async fn si_la_escritura_falla_no_se_marca_como_sincronizado_ni_se_rebota_el_viejo() {
        let clip = FakeClipboard::que_no_escribe("viejo");
        let salida = correr(&clip, |tx| async move {
            tx.send(Ok(clip_msg("nuevo"))).await.unwrap();
            tokio::time::sleep(UN_SONDEO).await;
        })
        .await;
        assert_eq!(clip.read().as_deref(), Some("viejo")); // no se escribió
                                                           // Si se hubiera marcado "nuevo" como sincronizado, el sondeo vería "viejo"
                                                           // como un cambio local y lo empujaría de vuelta al escritorio.
        assert!(salida.is_empty(), "no debe rebotar el viejo: {salida:?}");
    }
}
