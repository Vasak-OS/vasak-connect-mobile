//! Descubrimiento de escritorios de VasakOS por mDNS.
//!
//! El daemon del escritorio (`vasak-connect`) anuncia el servicio
//! `_vasakconnect._tcp` con un registro TXT que describe el aparato (id, nombre,
//! tipo, versión del protocolo y huella del certificado). Acá se navega ese
//! servicio y se traduce cada anuncio a un [`PeerInfo`] más su dirección.
//!
//! La decisión de qué es un anuncio válido NO vive acá: la toma
//! [`vasak_connect_protocol::pure::parse_peer_txt`], la misma función que el
//! daemon usa para lo contrario (armar el TXT). Este archivo sólo mueve datos de
//! los tipos de `mdns-sd` al mapa que esa función espera, y elige una dirección.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use mdns_sd::ServiceInfo;
use vasak_connect_protocol::pure::{device_id_from_fingerprint, parse_peer_txt};
use vasak_connect_protocol::wire::PeerInfo;

/// Un escritorio visto en la red: lo que anuncia y dónde contestarle.
pub struct Discovered {
    pub peer: PeerInfo,
    /// Dónde conectarse para parear. Se resuelve y se prueba acá, pero recién lo
    /// consume el pareo (PR2b): el descubrimiento sólo lista. `allow(dead_code)`
    /// para no partir la resolución de la dirección —ya probada— y rearmarla
    /// después. shortcut: el `allow` se saca al llegar el cliente TLS del pareo.
    #[allow(dead_code)]
    pub addr: SocketAddr,
    /// El nombre completo del servicio mDNS, para poder sacarlo de la lista
    /// cuando `mdns-sd` avise que desapareció (los eventos de salida sólo lo
    /// traen a él, no el `device_id`).
    pub fullname: String,
}

/// Pasa las propiedades TXT de `mdns-sd` al mapa `clave → valor` que espera
/// [`parse_peer_txt`]. `val_str` devuelve el valor como texto (las claves del
/// contrato son todas texto); `parse_peer_txt` descarta las vacías.
fn txt_map(info: &ServiceInfo) -> HashMap<String, String> {
    info.get_properties()
        .iter()
        .map(|p| (p.key().to_string(), p.val_str().to_string()))
        .collect()
}

/// Elige una dirección para contestarle al par: IPv4 si hay —es lo que una LAN
/// doméstica enruta sin configurar—, si no la primera que haya.
fn pick_addr(addresses: &[IpAddr], port: u16) -> Option<SocketAddr> {
    let ip = addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.first())?;
    Some(SocketAddr::new(*ip, port))
}

/// Traduce un servicio mDNS resuelto a un [`Discovered`], o `None` si el TXT no
/// describe un par válido (lo decide `parse_peer_txt`) o si no trae una dirección
/// con la que conectarse.
pub fn resolved(info: &ServiceInfo) -> Option<Discovered> {
    let peer = parse_peer_txt(&txt_map(info))?;
    // El `device_id` anunciado tiene que derivar de la huella anunciada. Un daemon
    // honesto lo arma así (`device_id_from_fingerprint`); si no coinciden, el
    // anuncio está mal formado o es tramposo y se descarta. Con esto el `device_id`
    // de un descubierto es siempre el derivado de la huella, y la interfaz puede
    // casar «ya vinculado» —que se guarda con el id derivado de la huella del
    // certificado— por `device_id` sin confundirse.
    if peer.device_id != device_id_from_fingerprint(&peer.fingerprint) {
        return None;
    }
    let addresses: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
    let addr = pick_addr(&addresses, info.get_port())?;
    Some(Discovered {
        peer,
        addr,
        fullname: info.get_fullname().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vasak_connect_protocol::wire::{DeviceKind, PROTOCOL_VERSION, SERVICE_TYPE};

    /// Una huella de ejemplo y el `device_id` que de ella deriva —como lo arma un
    /// daemon honesto—, para que los anuncios de prueba pasen el chequeo de
    /// consistencia id↔huella.
    const FP: &str = "AA:BB:CC:DD";

    /// Arma un `ServiceInfo` como el que publica el daemon, con el TXT del
    /// contrato, para probar la traducción sin una red de verdad.
    fn servicio(props: &[(String, String)]) -> ServiceInfo {
        let prestados: Vec<(&str, &str)> = props
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        ServiceInfo::new(
            SERVICE_TYPE,
            "escritorio-de-joaco",
            "escritorio-de-joaco.local.",
            "192.168.1.50",
            5544,
            &prestados[..],
        )
        .unwrap()
    }

    fn txt_valido() -> Vec<(String, String)> {
        vec![
            ("id".into(), device_id_from_fingerprint(FP)),
            ("name".into(), "Escritorio de Joaco".into()),
            ("kind".into(), "desktop".into()),
            ("proto".into(), "2".into()),
            ("fp".into(), FP.into()),
        ]
    }

    #[test]
    fn un_anuncio_valido_da_el_par_y_la_direccion() {
        let d = resolved(&servicio(&txt_valido())).expect("debería resolver");
        assert_eq!(d.peer.device_id, device_id_from_fingerprint(FP));
        assert_eq!(d.peer.name, "Escritorio de Joaco");
        assert_eq!(d.peer.kind, DeviceKind::Desktop);
        assert_eq!(d.peer.protocol_version, PROTOCOL_VERSION);
        assert_eq!(d.peer.fingerprint, FP);
        assert_eq!(
            d.addr,
            SocketAddr::new(IpAddr::from([192, 168, 1, 50]), 5544)
        );
        assert_eq!(d.fullname, "escritorio-de-joaco._vasakconnect._tcp.local.");
    }

    #[test]
    fn un_id_que_no_deriva_de_la_huella_se_descarta() {
        let mut props = txt_valido();
        // Un id que no sale de la huella: anuncio tramposo o mal formado.
        props.retain(|(k, _)| k != "id");
        props.push(("id".into(), "id-inventado".into()));
        assert!(resolved(&servicio(&props)).is_none());
    }

    #[test]
    fn sin_la_huella_el_anuncio_se_descarta() {
        let mut props = txt_valido();
        props.retain(|(k, _)| k != "fp");
        assert!(resolved(&servicio(&props)).is_none());
    }

    #[test]
    fn un_kind_desconocido_no_descarta_el_anuncio() {
        let mut props = txt_valido();
        props.retain(|(k, _)| k != "kind");
        props.push(("kind".into(), "smartwatch".into()));
        let d = resolved(&servicio(&props)).expect("debería resolver igual");
        assert_eq!(d.peer.kind, DeviceKind::Unknown);
    }

    #[test]
    fn prefiere_ipv4_entre_varias_direcciones() {
        let addrs = [
            IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
            IpAddr::from([10, 0, 0, 7]),
        ];
        let addr = pick_addr(&addrs, 5544).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::from([10, 0, 0, 7]), 5544));
    }

    #[test]
    fn sin_direcciones_no_hay_adonde_conectarse() {
        assert!(pick_addr(&[], 5544).is_none());
    }
}
