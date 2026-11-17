//! El canal teléfono↔escritorio del lado del teléfono.
//!
//! Por ahora: **descubrimiento**. Navega por mDNS los escritorios de VasakOS que
//! se anuncian en la red y mantiene la lista para la interfaz. El TLS mutuo y el
//! pareo (SAS/RFC-6189) llegan en el PR siguiente y reúsan la misma lógica pura
//! del protocolo (`vasak_connect_protocol::pure`) que el daemon.

mod discovery;

use std::collections::HashMap;
use std::sync::Mutex;

use mdns_sd::{ServiceDaemon, ServiceEvent};
use tauri::{AppHandle, Emitter, Manager, State};
use vasak_connect_protocol::wire::{PeerInfo, SERVICE_TYPE};

use discovery::Discovered;

/// El evento que se emite cada vez que cambia la lista de escritorios vistos. La
/// interfaz lo escucha y vuelve a pintar. El cuerpo es la lista completa (un
/// `Vec<PeerInfo>`), no un delta: redibujar con la lista entera es más simple y
/// la lista es chica.
const PEERS_CHANGED: &str = "peers-changed";

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
                        let inner = state.inner.lock().expect("estado envenenado");
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
    let mut inner = state.inner.lock().expect("estado envenenado");
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
            discovered_peers
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
