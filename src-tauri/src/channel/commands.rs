//! La capa Tauri del canal: los comandos que invoca la interfaz y la orquestación
//! del pareo (abrir el TLS, correr el handshake, persistir, avisar).
//!
//! Es I/O y `AppHandle` de punta a punta —se verifica contra el servicio real, no
//! con pruebas unitarias—, por eso la puerta de cobertura excluye los
//! `commands.rs`. La lógica que SÍ se prueba vive en los otros módulos del canal
//! (framing, pareo, identidad, almacén, descubrimiento) y en `super`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mdns_sd::ServiceDaemon;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot};
use vasak_connect_protocol::wire::{DeviceKind, Message, PeerInfo, PROTOCOL_VERSION, SERVICE_TYPE};

use super::identity::{self, Identity};
use super::store::{self, PairedPeer};
use super::transport::{self, Session, SessionError};
use super::{
    apply_event, pairing, snapshot, ChannelState, PAIRING_RESULT, PAIRING_SAS, PEERS_CHANGED,
    SELF_NAME,
};

/// Cuánto se le da a un pareo antes de cortarlo. Un escritorio que acepta el TCP
/// pero nunca completa el TLS —o se queda callado— no puede bloquear para siempre:
/// sin esto `pairing_active` quedaría tomado y todo pareo posterior fallaría.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(60);

// ── Descubrimiento ───────────────────────────────────────────────────────────

/// Empieza a navegar por mDNS. Idempotente: si ya hay un demonio, no abre otro.
#[tauri::command]
fn discovery_start(app: AppHandle, state: State<'_, ChannelState>) -> Result<(), String> {
    let receiver = {
        let mut inner = state.inner.lock().map_err(|_| "estado envenenado")?;
        if inner.daemon.is_some() {
            return Ok(());
        }
        let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
        let receiver = daemon.browse(SERVICE_TYPE).map_err(|e| e.to_string())?;
        inner.daemon = Some(daemon);
        receiver
    };

    let app = app.clone();
    std::thread::spawn(move || {
        // `recv` falla cuando el demonio se apaga (`discovery_stop`) y cierra el
        // canal: ahí el hilo termina solo.
        while let Ok(event) = receiver.recv() {
            let Some(state) = app.try_state::<ChannelState>() else {
                break;
            };
            // Recuperar un candado envenenado en vez de `expect`: paniquear acá
            // mataría el hilo del browse y el descubrimiento se apagaría en silencio.
            let cambio = {
                let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
                apply_event(&mut inner, event)
            };
            if cambio {
                let list = {
                    let inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
                    snapshot(&inner)
                };
                let _ = app.emit(PEERS_CHANGED, list);
            }
        }
    });
    Ok(())
}

/// Deja de navegar y olvida lo visto. Apagar el demonio cierra el browse y su hilo.
#[tauri::command]
fn discovery_stop(app: AppHandle, state: State<'_, ChannelState>) -> Result<(), String> {
    {
        let mut inner = state.inner.lock().map_err(|_| "estado envenenado")?;
        if let Some(daemon) = inner.daemon.take() {
            let _ = daemon.shutdown();
        }
        inner.peers.clear();
    }
    let _ = app.emit(PEERS_CHANGED, Vec::<PeerInfo>::new());
    Ok(())
}

/// La lista actual de escritorios vistos, para pedirla al montar sin esperar un
/// evento.
#[tauri::command]
fn discovered_peers(state: State<'_, ChannelState>) -> Result<Vec<PeerInfo>, String> {
    let inner = state.inner.lock().map_err(|_| "estado envenenado")?;
    Ok(snapshot(&inner))
}

// ── Pareo ────────────────────────────────────────────────────────────────────

/// La identidad TLS del teléfono: la del caché, o se carga/crea del disco y se
/// cachea. No tiene `.await` con el candado tomado.
async fn identity_for(
    app: &AppHandle,
    state: &State<'_, ChannelState>,
) -> Result<Arc<Identity>, String> {
    if let Some(id) = state
        .inner
        .lock()
        .map_err(|_| "estado envenenado")?
        .identity
        .clone()
    {
        return Ok(id);
    }
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let id = Arc::new(
        identity::load_or_create(&dir)
            .await
            .map_err(|e| e.to_string())?,
    );
    state
        .inner
        .lock()
        .map_err(|_| "estado envenenado")?
        .identity = Some(id.clone());
    Ok(id)
}

/// Libera el pareo en curso (guardia + canal de confirmación). Se llama al terminar
/// y en cualquier salida temprana después de haberlo reservado.
fn release_pairing(state: &State<'_, ChannelState>) {
    if let Ok(mut inner) = state.inner.lock() {
        inner.pairing_active = false;
        inner.pending_confirm = None;
    }
}

/// Lo que viaja en el evento [`PAIRING_RESULT`].
#[derive(Clone, Serialize)]
struct PairingResultPayload {
    device_id: String,
    /// `paired`, `rejected_local`, `rejected_peer`, `aborted` o `error`.
    status: &'static str,
    message: Option<String>,
}

/// Pide parear con un escritorio descubierto. Arranca una tarea que abre el TLS y
/// corre el pareo; la interfaz sigue por los eventos [`PAIRING_SAS`] y
/// [`PAIRING_RESULT`]. Devuelve ya, sin esperar a que termine.
#[tauri::command]
async fn pair_request(
    app: AppHandle,
    state: State<'_, ChannelState>,
    device_id: String,
) -> Result<(), String> {
    let addr = {
        let inner = state.inner.lock().map_err(|_| "estado envenenado")?;
        inner.peers.get(&device_id).map(|d| d.addr)
    }
    .ok_or("ese escritorio ya no está en la lista")?;

    // Reservar el pareo ANTES de cargar la identidad: dos pedidos en frío no pueden
    // generar y persistir dos identidades distintas (C5), ni pisarse el guardia (C6).
    {
        let mut inner = state.inner.lock().map_err(|_| "estado envenenado")?;
        if inner.pairing_active {
            return Err("ya hay un pareo en curso".to_string());
        }
        inner.pairing_active = true;
    }

    let identity = match identity_for(&app, &state).await {
        Ok(id) => id,
        Err(e) => {
            release_pairing(&state);
            return Err(e);
        }
    };
    let own = PeerInfo {
        device_id: identity.device_id.clone(),
        name: SELF_NAME.to_string(),
        kind: DeviceKind::Phone,
        protocol_version: PROTOCOL_VERSION,
        fingerprint: identity.fingerprint.clone(),
    };

    let (confirm_tx, confirm_rx) = oneshot::channel::<bool>();
    {
        state
            .inner
            .lock()
            .map_err(|_| "estado envenenado")?
            .pending_confirm = Some(confirm_tx);
    }

    // El SAS se reenvía como evento en una tarea que se puede esperar, para que el
    // resultado nunca salga antes que un SAS ya encolado (C13).
    let (sas_tx, mut sas_rx) = mpsc::unbounded_channel::<String>();
    let app_sas = app.clone();
    let forwarder = tauri::async_runtime::spawn(async move {
        while let Some(code) = sas_rx.recv().await {
            let _ = app_sas.emit(PAIRING_SAS, code);
        }
    });

    let dir = match app.path().app_local_data_dir() {
        Ok(dir) => dir,
        Err(e) => {
            release_pairing(&state);
            return Err(e.to_string());
        }
    };
    let app_task = app.clone();
    tauri::async_runtime::spawn(async move {
        // Con tope de tiempo: un par que nunca completa no bloquea el canal (C10).
        let outcome = match tokio::time::timeout(
            PAIRING_TIMEOUT,
            pair_session(addr, identity, own, sas_tx, confirm_rx),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err("el escritorio no respondió a tiempo".to_string()),
        };
        // `pair_session` ya soltó su `sas_tx`, así que el reenviador terminó: se lo
        // espera antes de emitir el resultado para que no llegue un SAS después.
        let _ = forwarder.await;
        finish_pairing(&app_task, &dir, &device_id, outcome).await;
    });

    Ok(())
}

/// Abre el TLS, parte la sesión en una tarea lectora y una escritora, y corre el
/// pareo sobre los canales que las conectan.
async fn pair_session(
    addr: SocketAddr,
    identity: Arc<Identity>,
    own: PeerInfo,
    sas_tx: mpsc::UnboundedSender<String>,
    confirm_rx: oneshot::Receiver<bool>,
) -> Result<pairing::Outcome, String> {
    let session = Session::connect(addr, &identity)
        .await
        .map_err(|e| e.to_string())?;
    let peer_fingerprint = session.peer_fingerprint().to_string();
    let (read_half, write_half) = session.split();

    let (in_tx, in_rx) = mpsc::channel::<Result<Message, SessionError>>(16);
    let (out_tx, out_rx) = mpsc::channel::<Message>(16);
    tauri::async_runtime::spawn(transport::reader_loop(read_half, in_tx));
    tauri::async_runtime::spawn(transport::writer_loop(write_half, out_rx));

    pairing::run(&peer_fingerprint, &own, in_rx, out_tx, sas_tx, confirm_rx)
        .await
        .map_err(|e| e.to_string())
}

/// Cierra un pareo: libera el guardia, persiste el par si se fijó, y avisa a la
/// interfaz cómo terminó.
async fn finish_pairing(
    app: &AppHandle,
    dir: &Path,
    device_id: &str,
    outcome: Result<pairing::Outcome, String>,
) {
    if let Some(state) = app.try_state::<ChannelState>() {
        if let Ok(mut inner) = state.inner.lock() {
            inner.pairing_active = false;
            inner.pending_confirm = None;
        }
    }

    let payload = match outcome {
        Ok(pairing::Outcome::Paired(peer)) => {
            let message = store::add(dir, peer).await.err().map(|e| e.to_string());
            PairingResultPayload {
                device_id: device_id.to_string(),
                // Si falló persistir, el par quedó fijado en memoria pero no en
                // disco: se reporta como error para que la persona reintente.
                status: if message.is_some() { "error" } else { "paired" },
                message,
            }
        }
        Ok(pairing::Outcome::RejectedLocally) => PairingResultPayload {
            device_id: device_id.to_string(),
            status: "rejected_local",
            message: None,
        },
        Ok(pairing::Outcome::RejectedByPeer) => PairingResultPayload {
            device_id: device_id.to_string(),
            status: "rejected_peer",
            message: None,
        },
        Ok(pairing::Outcome::Aborted) => PairingResultPayload {
            device_id: device_id.to_string(),
            status: "aborted",
            message: None,
        },
        Err(error) => PairingResultPayload {
            device_id: device_id.to_string(),
            status: "error",
            message: Some(error),
        },
    };
    let _ = app.emit(PAIRING_RESULT, payload);
}

/// La decisión de la persona sobre el SAS en curso. Falla si no hay un pareo
/// esperando.
#[tauri::command]
fn pair_confirm(state: State<'_, ChannelState>, accept: bool) -> Result<(), String> {
    let tx = {
        let mut inner = state.inner.lock().map_err(|_| "estado envenenado")?;
        inner.pending_confirm.take()
    }
    .ok_or("no hay un pareo esperando confirmación")?;
    tx.send(accept).map_err(|_| "el pareo ya había terminado")?;
    Ok(())
}

/// Los escritorios ya pareados y persistidos.
#[tauri::command]
async fn paired_peers(app: AppHandle) -> Result<Vec<PairedPeer>, String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    Ok(store::load(&dir).await)
}

/// Registra el estado del canal y sus comandos en el `Builder`.
///
/// Concreto a `Wry` a propósito: `generate_handler!` resuelve `AppHandle`
/// (= `AppHandle<Wry>`) contra un runtime concreto; en una función genérica no
/// casaría. La app usa `Wry` (ver `construir_app`).
pub fn init(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    builder
        .manage(ChannelState::default())
        .invoke_handler(tauri::generate_handler![
            discovery_start,
            discovery_stop,
            discovered_peers,
            pair_request,
            pair_confirm,
            paired_peers
        ])
}
