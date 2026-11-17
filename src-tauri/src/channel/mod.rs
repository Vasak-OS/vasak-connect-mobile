//! El canal teléfono↔escritorio del lado del teléfono.
//!
//! Dos cosas: **descubrimiento** (navegar por mDNS los escritorios de VasakOS) y
//! **pareo** (abrir el TLS mutuo con uno y fijar su huella tras confirmar el SAS).
//! Toda la lógica que decide —framing, pinning, compromiso, derivación del SAS y
//! la máquina de estados del pareo— es `vasak_connect_protocol::pure`, la misma
//! que corre el daemon; acá vive el I/O (mDNS, TLS, DH, disco) y el puente con la
//! interfaz.

mod discovery;
mod identity;
mod pairing;
mod store;
mod transport;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot};
use vasak_connect_protocol::wire::{DeviceKind, PeerInfo, PROTOCOL_VERSION, SERVICE_TYPE};

use discovery::Discovered;
use identity::Identity;
use store::PairedPeer;
use transport::Session;

/// El nombre con el que el teléfono se presenta al escritorio (lo que la persona
/// ve al confirmar el pareo).
///
/// shortcut: un nombre fijo. El nombre real del aparato (modelo, o el que puso la
/// persona) necesita una API de plataforma (Android/iOS); va cuando el pareo esté
/// andando en dispositivo.
const SELF_NAME: &str = "Teléfono VasakOS";

/// El evento que se emite cada vez que cambia la lista de escritorios vistos. La
/// interfaz lo escucha y vuelve a pintar. El cuerpo es la lista completa (un
/// `Vec<PeerInfo>`), no un delta: redibujar con la lista entera es más simple y
/// la lista es chica.
const PEERS_CHANGED: &str = "peers-changed";

/// El SAS (código de seis dígitos) a mostrarle a la persona durante un pareo. La
/// interfaz lo escucha, lo muestra y espera su confirmación (`pair_confirm`).
const PAIRING_SAS: &str = "pairing-sas";

/// Cómo terminó un pareo. La interfaz lo escucha para cerrar el diálogo del SAS.
const PAIRING_RESULT: &str = "pairing-result";

/// Estado del canal, administrado por Tauri. El `Mutex` alcanza: las operaciones
/// son cortas (tomar el candado, mutar el mapa, soltar) y no hay `.await` adentro.
#[derive(Default)]
pub struct ChannelState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// El demonio mDNS mientras el descubrimiento está activo. Soltarlo (o
    /// `shutdown`) cierra el canal del browse y termina su hilo.
    daemon: Option<ServiceDaemon>,
    /// Escritorios vistos, por `device_id`.
    peers: HashMap<String, Discovered>,
    /// La identidad TLS del teléfono, cargada del disco la primera vez que hace
    /// falta y cacheada (generarla es caro y tiene que ser estable entre pareos).
    identity: Option<Arc<Identity>>,
    /// El canal por el que `pair_confirm` le pasa la decisión de la persona al
    /// pareo en curso. `Some` sólo mientras hay un pareo esperando confirmación.
    pending_confirm: Option<oneshot::Sender<bool>>,
}

impl Inner {
    /// Anota (o reemplaza) un escritorio visto. Devuelve `true` siempre: la lista
    /// que ve la interfaz cambió (apareció o se actualizó un par).
    fn remember(&mut self, d: Discovered) -> bool {
        self.peers.insert(d.peer.device_id.clone(), d);
        true
    }

    /// Olvida el escritorio cuyo servicio mDNS coincide. `true` si sacó algo, para
    /// no reemitir por un evento de salida de algo que no estaba.
    fn forget(&mut self, fullname: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|_, d| d.fullname != fullname);
        self.peers.len() != before
    }
}

/// La lista que ve la interfaz, derivada del estado. Sólo lo que anuncia cada
/// par; la dirección se queda del lado de Rust.
fn snapshot(inner: &Inner) -> Vec<PeerInfo> {
    inner.peers.values().map(|d| d.peer.clone()).collect()
}

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
            if apply_event(&app, event) {
                if let Some(state) = app.try_state::<ChannelState>() {
                    let list = {
                        // Recuperar un candado envenenado en vez de `expect`: si un
                        // tenedor paniqueó, el peor caso es una lista de
                        // descubiertos a medio actualizar, no un invariante roto.
                        // Paniquear acá mataría el hilo del browse y el
                        // descubrimiento se apagaría en silencio.
                        let inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
                        snapshot(&inner)
                    };
                    let _ = app.emit(PEERS_CHANGED, list);
                }
            }
        }
    });

    Ok(())
}

/// Aplica un evento del browse al estado. Devuelve `true` si la lista cambió (hay
/// que reemitir), `false` si el evento no la tocó.
fn apply_event(app: &AppHandle, event: ServiceEvent) -> bool {
    let Some(state) = app.try_state::<ChannelState>() else {
        return false;
    };
    // Recuperar un candado envenenado (ver el bucle del browse): no paniquear el
    // hilo del descubrimiento por el estado de un tenedor anterior.
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    match event {
        ServiceEvent::ServiceResolved(info) => match discovery::resolved(&info) {
            Some(d) => inner.remember(d),
            None => false,
        },
        // Los eventos de salida sólo traen el nombre completo del servicio, no el
        // `device_id`: se saca la entrada cuyo `fullname` coincide.
        ServiceEvent::ServiceRemoved(_, fullname) => inner.forget(&fullname),
        _ => false,
    }
}

/// Deja de navegar y olvida lo visto. Apagar el demonio cierra el browse y su
/// hilo termina.
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

/// La lista actual de escritorios vistos, para que la interfaz pueda pedirla al
/// montar sin esperar al primer evento.
#[tauri::command]
fn discovered_peers(state: State<'_, ChannelState>) -> Result<Vec<PeerInfo>, String> {
    let inner = state.inner.lock().map_err(|_| "estado envenenado")?;
    Ok(snapshot(&inner))
}

/// La identidad TLS del teléfono: la del caché, o se carga/crea del disco y se
/// cachea. Generarla es caro y tiene que ser estable, por eso se hace una vez.
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

/// Lo que viaja en el evento [`PAIRING_RESULT`].
#[derive(Clone, Serialize)]
struct PairingResultPayload {
    device_id: String,
    /// `paired`, `rejected_local`, `rejected_peer`, `aborted` o `error`.
    status: &'static str,
    message: Option<String>,
}

/// Pide parear con un escritorio descubierto. Arranca una tarea que abre el TLS y
/// corre el pareo; la interfaz sigue por los eventos [`PAIRING_SAS`] (mostrar el
/// código y pedir confirmación) y [`PAIRING_RESULT`] (cómo terminó). Devuelve ya,
/// sin esperar a que el pareo termine.
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

    let identity = identity_for(&app, &state).await?;
    let own = PeerInfo {
        device_id: identity.device_id.clone(),
        name: SELF_NAME.to_string(),
        kind: DeviceKind::Phone,
        protocol_version: PROTOCOL_VERSION,
        fingerprint: identity.fingerprint.clone(),
    };

    // El canal por el que `pair_confirm` traerá la decisión de la persona.
    let (confirm_tx, confirm_rx) = oneshot::channel::<bool>();
    {
        let mut inner = state.inner.lock().map_err(|_| "estado envenenado")?;
        inner.pending_confirm = Some(confirm_tx);
    }

    // El SAS que el pareo quiera mostrar se reenvía como evento.
    let (sas_tx, mut sas_rx) = mpsc::unbounded_channel::<String>();
    let app_sas = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(code) = sas_rx.recv().await {
            let _ = app_sas.emit(PAIRING_SAS, code);
        }
    });

    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let app_task = app.clone();
    tauri::async_runtime::spawn(async move {
        let outcome = async {
            let mut session = Session::connect(addr, &identity)
                .await
                .map_err(|e| e.to_string())?;
            pairing::run(&mut session, &own, sas_tx, confirm_rx)
                .await
                .map_err(|e| e.to_string())
        }
        .await;
        finish_pairing(&app_task, &dir, &device_id, outcome).await;
    });

    Ok(())
}

/// Cierra un pareo: limpia el canal de confirmación, persiste el par si se fijó, y
/// avisa a la interfaz cómo terminó.
async fn finish_pairing(
    app: &AppHandle,
    dir: &std::path::Path,
    device_id: &str,
    outcome: Result<pairing::Outcome, String>,
) {
    if let Some(state) = app.try_state::<ChannelState>() {
        if let Ok(mut inner) = state.inner.lock() {
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

/// La decisión de la persona sobre el SAS en curso: `true` acepta, `false`
/// rechaza. Falla si no hay un pareo esperando.
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
/// Concreto a `Wry` a propósito: `generate_handler!` genera envoltorios que
/// resuelven `AppHandle` (= `AppHandle<Wry>`) contra un runtime concreto; dentro
/// de una función genérica sobre `R` no casarían. La app usa `Wry` (ver
/// `construir_app`), así que no se pierde nada.
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

#[cfg(test)]
mod tests {
    use super::*;
    use vasak_connect_protocol::wire::{DeviceKind, PROTOCOL_VERSION};

    fn peer(id: &str) -> PeerInfo {
        PeerInfo {
            device_id: id.to_string(),
            name: format!("Escritorio {id}"),
            kind: DeviceKind::Desktop,
            protocol_version: PROTOCOL_VERSION,
            fingerprint: "AA:BB".to_string(),
        }
    }

    fn discovered(id: &str, fullname: &str) -> Discovered {
        Discovered {
            peer: peer(id),
            addr: "192.168.1.9:5544".parse().unwrap(),
            fullname: fullname.to_string(),
        }
    }

    #[test]
    fn el_snapshot_lista_solo_lo_que_anuncia_cada_par() {
        let mut inner = Inner::default();
        inner.remember(discovered("a", "a.local."));
        inner.remember(discovered("b", "b.local."));
        let list = snapshot(&inner);
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|p| p.protocol_version == PROTOCOL_VERSION));
    }

    #[test]
    fn un_mismo_device_id_no_se_duplica() {
        let mut inner = Inner::default();
        inner.remember(discovered("a", "a.local."));
        // Reaparece con otro nombre de instancia pero el mismo id.
        inner.remember(discovered("a", "a-2.local."));
        assert_eq!(snapshot(&inner).len(), 1);
    }

    #[test]
    fn olvidar_por_fullname_saca_solo_el_que_coincide() {
        let mut inner = Inner::default();
        inner.remember(discovered("a", "a.local."));
        inner.remember(discovered("b", "b.local."));

        assert!(inner.forget("a.local."));
        let list = snapshot(&inner);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].device_id, "b");
    }

    #[test]
    fn olvidar_algo_que_no_esta_no_cambia_la_lista() {
        let mut inner = Inner::default();
        inner.remember(discovered("a", "a.local."));
        // Un evento de salida de un servicio que nunca se vio: no hay que reemitir.
        assert!(!inner.forget("fantasma.local."));
        assert_eq!(snapshot(&inner).len(), 1);
    }
}
