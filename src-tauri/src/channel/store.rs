//! Los escritorios ya pareados, persistidos en el teléfono.
//!
//! El pareo termina fijando la **huella** del certificado del escritorio: a
//! partir de ahí ese aparato es de confianza y se lo reconoce por su huella en
//! cada reconexión (el pinning lo hace `pure::evaluate_peer_cert`). Acá se guarda
//! esa lista en un JSON del directorio privado de la app.
//!
//! shortcut: lista en un archivo del dir privado (sandbox de la app). La huella
//! es pública —no es un secreto— así que el archivo no necesita cifrado; si más
//! adelante se guarda algo sensible por par, va al keystore de la plataforma.

use std::path::Path;

use serde::{Deserialize, Serialize};
use vasak_connect_protocol::wire::DeviceKind;

/// Un escritorio de confianza: su identidad estable, el nombre para mostrar y la
/// huella fijada que lo autentica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedPeer {
    pub device_id: String,
    pub name: String,
    pub kind: DeviceKind,
    pub fingerprint: String,
}

const FILE: &str = "paired.json";
/// El temporal del escritorio atómico. Se escribe entero y recién después se
/// renombra sobre `paired.json`: así un corte a mitad de escritura no deja el
/// archivo real truncado (que `load` leería como vacío y perdería los pares).
const FILE_TMP: &str = "paired.json.tmp";

/// Inserta o reemplaza un par por `device_id`. Reemplazar es a propósito: si un
/// escritorio conocido se vuelve a parear (otra huella), queda la nueva.
fn upsert(mut peers: Vec<PairedPeer>, peer: PairedPeer) -> Vec<PairedPeer> {
    peers.retain(|p| p.device_id != peer.device_id);
    peers.push(peer);
    peers
}

/// Carga la lista. Si el archivo no está o no parsea, devuelve vacío: una lista
/// corrupta no debe impedir arrancar ni parear de nuevo (peor caso, se re-parea).
pub async fn load(dir: &Path) -> Vec<PairedPeer> {
    match tokio::fs::read(dir.join(FILE)).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Agrega (o reemplaza) un par y persiste la lista entera, de forma atómica:
/// escribe un temporal completo y lo renombra sobre el archivo real. El `rename`
/// en el mismo directorio es atómico, así que `load` ve o la lista vieja entera o
/// la nueva entera, nunca una a medias.
pub async fn add(dir: &Path, peer: PairedPeer) -> std::io::Result<()> {
    let peers = upsert(load(dir).await, peer);
    let bytes = serde_json::to_vec_pretty(&peers).expect("Vec<PairedPeer> siempre serializa");
    tokio::fs::create_dir_all(dir).await?;
    let tmp = dir.join(FILE_TMP);
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, dir.join(FILE)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, fp: &str) -> PairedPeer {
        PairedPeer {
            device_id: id.to_string(),
            name: format!("Escritorio {id}"),
            kind: DeviceKind::Desktop,
            fingerprint: fp.to_string(),
        }
    }

    #[test]
    fn upsert_agrega_uno_nuevo() {
        let lista = upsert(vec![], peer("a", "AA"));
        assert_eq!(lista.len(), 1);
        assert_eq!(lista[0].device_id, "a");
    }

    #[test]
    fn upsert_reemplaza_la_huella_de_un_id_conocido() {
        let lista = upsert(vec![peer("a", "AA")], peer("a", "BB"));
        assert_eq!(lista.len(), 1);
        assert_eq!(lista[0].fingerprint, "BB");
    }

    #[tokio::test]
    async fn carga_vacio_si_no_hay_archivo() {
        let dir = std::env::temp_dir().join(format!("vcm-store-none-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        assert!(load(&dir).await.is_empty());
    }

    #[tokio::test]
    async fn agrega_y_vuelve_a_leer() {
        let dir = std::env::temp_dir().join(format!("vcm-store-rw-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;

        add(&dir, peer("a", "AA")).await.unwrap();
        add(&dir, peer("b", "BB")).await.unwrap();
        let leidos = load(&dir).await;
        assert_eq!(leidos.len(), 2);
        assert!(leidos
            .iter()
            .any(|p| p.device_id == "b" && p.fingerprint == "BB"));

        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }

    #[tokio::test]
    async fn una_lista_corrupta_se_lee_como_vacia() {
        let dir = std::env::temp_dir().join(format!("vcm-store-bad-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join(FILE), b"no es json")
            .await
            .unwrap();
        assert!(load(&dir).await.is_empty());
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }
}
