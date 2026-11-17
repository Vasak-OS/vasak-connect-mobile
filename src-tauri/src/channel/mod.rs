//! El canal teléfono↔escritorio del lado del teléfono.
//!
//! Dos cosas: **descubrimiento** (navegar por mDNS los escritorios de VasakOS) y
//! **pareo** (abrir el TLS mutuo con uno y fijar su huella tras confirmar el SAS).
//! Toda la lógica que decide —framing, pinning, compromiso, derivación del SAS y
//! la máquina de estados del pareo— es `vasak_connect_protocol::pure`, la misma
//! que corre el daemon; acá vive el I/O (mDNS, TLS, DH, disco) y el puente con la
//! interfaz.
//!
//! Este archivo tiene el **estado** del canal y la lógica que se puede prober sin
//! una ventana ni una red. La capa que toca Tauri y los sockets —los comandos y la
//! orquestación del pareo— vive en [`commands`], que la puerta de cobertura excluye
//! (se verifica contra el servicio real, no con pruebas unitarias).

mod commands;
mod discovery;
mod identity;
mod pairing;
mod store;
mod transport;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mdns_sd::{ServiceDaemon, ServiceEvent};
use tokio::sync::oneshot;
use vasak_connect_protocol::wire::PeerInfo;

use discovery::Discovered;
use identity::Identity;

pub use commands::init;

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
    /// Hay un pareo en curso (de `pair_request` hasta que termina). Es el guardia
    /// de «uno a la vez»: se reserva ANTES de cargar la identidad y se libera recién
    /// al terminar. Se lleva aparte de `pending_confirm` a propósito: `pair_confirm`
    /// consume el `pending_confirm`, pero el pareo sigue vivo esperando al par, así
    /// que el guardia no puede depender de que esa ranura siga ocupada.
    pairing_active: bool,
    /// El canal por el que `pair_confirm` le pasa la decisión de la persona al
    /// pareo en curso. `Some` sólo mientras hay un pareo esperando confirmación.
    pending_confirm: Option<oneshot::Sender<bool>>,
    /// La tarea del pareo en curso, para poder cancelarla (`pair_cancel`): mientras
    /// se conecta no hay SAS que rechazar, así que la cancelación es la única salida
    /// de la persona antes del tope de tiempo.
    pairing_task: Option<tauri::async_runtime::JoinHandle<()>>,
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

/// Aplica un evento del browse al estado. Devuelve `true` si la lista cambió (hay
/// que reemitir), `false` si el evento no la tocó. Puro sobre el estado: el hilo
/// del browse toma el candado y llama acá.
fn apply_event(inner: &mut Inner, event: ServiceEvent) -> bool {
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

    #[test]
    fn apply_event_saca_el_par_al_recibir_su_salida() {
        let mut inner = Inner::default();
        inner.remember(discovered("a", "a.local."));
        let cambio = apply_event(
            &mut inner,
            ServiceEvent::ServiceRemoved("_vasakconnect._tcp.local.".into(), "a.local.".into()),
        );
        assert!(cambio);
        assert!(snapshot(&inner).is_empty());
    }

    #[test]
    fn apply_event_ignora_los_eventos_que_no_cambian_la_lista() {
        let mut inner = Inner::default();
        // `SearchStarted` no toca la lista de descubiertos.
        let cambio = apply_event(&mut inner, ServiceEvent::SearchStarted("x".into()));
        assert!(!cambio);
    }
}
