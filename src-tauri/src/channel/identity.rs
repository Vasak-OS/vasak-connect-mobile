//! La identidad TLS de larga vida del teléfono.
//!
//! Un certificado autofirmado con su clave privada, como el del daemon: no lo
//! valida ninguna CA, la seguridad la da el *pinning* de la huella en el pareo.
//! En el escritorio la clave vive en el Secret Service (`vasak-keyring`); en el
//! teléfono no hay Secret Service ni `~/.config`, así que la clave y el
//! certificado van al directorio de datos **privado** de la app (sandbox
//! por-app, que Android/iOS aíslan de las demás).
//!
//! shortcut: clave en un archivo del dir privado, protegida sólo por el sandbox
//! de la app. El endurecimiento es moverla al Android Keystore / iOS Keychain
//! (hardware-backed); va cuando el pareo esté andando en dispositivo.
//!
//! El cálculo de la huella y del `device_id` sale de
//! [`vasak_connect_protocol::pure`], la misma del daemon; acá sólo se genera el
//! par y se lo guarda.

use std::path::Path;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use vasak_connect_protocol::pure::{device_id_from_fingerprint, fingerprint_from_der};
use zeroize::Zeroizing;

/// El archivo con la identidad dentro del dir privado de la app. El certificado y
/// la clave van **juntos en un solo archivo**, escrito de forma atómica (temporal
/// + `rename`): así no puede quedar una escritura a medias (un certificado
/// truncado) ni un certificado de una generación con la clave de otra. O está el
/// par entero y consistente, o no está.
const IDENTITY_FILE: &str = "connect-identity.bin";
const IDENTITY_TMP: &str = "connect-identity.bin.tmp";

/// La identidad cargada: lo que necesita rustls (certificado y clave) más la
/// huella y el `device_id` que se derivan del certificado.
pub struct Identity {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    /// SHA-256 del DER del certificado, con dos puntos, como en
    /// [`vasak_connect_protocol::wire::PeerInfo::fingerprint`].
    pub fingerprint: String,
    /// Identificador estable derivado de la huella.
    pub device_id: String,
}

impl Identity {
    /// Arma la identidad desde el certificado y la clave en DER, derivando la
    /// huella y el `device_id`. No toca disco. La clave llega envuelta en
    /// [`Zeroizing`] para que esa copia intermedia se borre al salir.
    fn from_parts(cert_der: Vec<u8>, key_pkcs8_der: Zeroizing<Vec<u8>>) -> Self {
        let fingerprint = fingerprint_from_der(&cert_der);
        let device_id = device_id_from_fingerprint(&fingerprint);
        Identity {
            cert_der: CertificateDer::from(cert_der),
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8_der.to_vec())),
            fingerprint,
            device_id,
        }
    }
}

/// Errores al cargar o crear la identidad. Ninguno hace entrar en pánico.
#[derive(Debug)]
pub enum IdentityError {
    Generate(rcgen::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Generate(err) => write!(f, "no se pudo generar el certificado: {err}"),
            IdentityError::Io(err) => write!(f, "identidad en disco: {err}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Genera un par nuevo: certificado y clave en DER. La clave es ECDSA P-256 (el
/// valor por omisión de `rcgen`), que el proveedor `ring` de rustls firma. El
/// único SAN no se usa —no hay validación de nombre—, está sólo para que el
/// certificado sea bien formado.
fn generate() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), rcgen::Error> {
    let certified = rcgen::generate_simple_self_signed(vec!["vasak-connect-mobile".to_string()])?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = Zeroizing::new(certified.signing_key.serialize_der());
    Ok((cert_der, key_der))
}

/// Empaqueta el par en un solo blob: largo del certificado (4 bytes big-endian) +
/// certificado + clave. Guardar las dos piezas juntas y de una es lo que hace
/// imposible el par desapareado.
fn encode(cert_der: &[u8], key_pkcs8_der: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + cert_der.len() + key_pkcs8_der.len());
    out.extend_from_slice(&(cert_der.len() as u32).to_be_bytes());
    out.extend_from_slice(cert_der);
    out.extend_from_slice(key_pkcs8_der);
    out
}

/// Deshace [`encode`]. `None` si el blob está truncado o mal formado —una escritura
/// vieja a medias, o basura—: el que llama regenera en vez de cargar algo roto.
fn decode(blob: &[u8]) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let header: [u8; 4] = blob.get(..4)?.try_into().ok()?;
    let cert_len = u32::from_be_bytes(header) as usize;
    let cert = blob.get(4..4 + cert_len)?.to_vec();
    let key = blob.get(4 + cert_len..)?.to_vec();
    if cert.is_empty() || key.is_empty() {
        return None;
    }
    Some((cert, Zeroizing::new(key)))
}

/// Carga la identidad del dir dado, o la crea y la guarda si falta o está rota.
///
/// El par vive en un solo archivo escrito de forma atómica (temporal + `rename`):
/// o está entero y consistente, o no está. Un blob truncado o mal formado (de una
/// escritura vieja interrumpida, o basura) no se carga: se regenera. Así nunca se
/// usa un certificado a medias ni una clave que no corresponde al certificado.
pub async fn load_or_create(dir: &Path) -> Result<Identity, IdentityError> {
    let path = dir.join(IDENTITY_FILE);

    if let Ok(blob) = tokio::fs::read(&path).await {
        if let Some((cert, key)) = decode(&blob) {
            return Ok(Identity::from_parts(cert, key));
        }
    }

    let (cert_der, key_der) = generate().map_err(IdentityError::Generate)?;
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(IdentityError::Io)?;
    // El blob lleva la clave: se envuelve en `Zeroizing` para que su copia
    // serializada se borre al salir.
    let blob = Zeroizing::new(encode(&cert_der, &key_der));
    let tmp = dir.join(IDENTITY_TMP);
    tokio::fs::write(&tmp, &blob[..])
        .await
        .map_err(IdentityError::Io)?;
    tokio::fs::rename(&tmp, &path)
        .await
        .map_err(IdentityError::Io)?;
    Ok(Identity::from_parts(cert_der, key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_identidad_generada_deriva_huella_e_id_del_certificado() {
        let (cert, key) = generate().unwrap();
        let identity = Identity::from_parts(cert.clone(), key);
        assert_eq!(identity.fingerprint, fingerprint_from_der(&cert));
        assert_eq!(
            identity.device_id,
            device_id_from_fingerprint(&identity.fingerprint)
        );
        assert_eq!(identity.cert_der.as_ref(), cert.as_slice());
        assert!(matches!(identity.key_der, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn dos_identidades_generadas_no_comparten_huella() {
        let (a, _) = generate().unwrap();
        let (b, _) = generate().unwrap();
        assert_ne!(fingerprint_from_der(&a), fingerprint_from_der(&b));
    }

    #[tokio::test]
    async fn crea_y_despues_carga_la_misma_identidad() {
        let dir = std::env::temp_dir().join(format!("vcm-id-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;

        let creada = load_or_create(&dir).await.unwrap();
        let cargada = load_or_create(&dir).await.unwrap();
        // La segunda vez lee el archivo, no regenera: misma huella y device_id.
        assert_eq!(creada.fingerprint, cargada.fingerprint);
        assert_eq!(creada.device_id, cargada.device_id);

        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }

    #[tokio::test]
    async fn un_archivo_de_identidad_roto_se_regenera() {
        let dir = std::env::temp_dir().join(format!("vcm-id-regen-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;

        let primera = load_or_create(&dir).await.unwrap();
        // Simula una escritura vieja a medias: el archivo queda truncado.
        tokio::fs::write(dir.join(IDENTITY_FILE), b"\x00\x00\x10\x00corto")
            .await
            .unwrap();
        let segunda = load_or_create(&dir).await.unwrap();
        // No carga el roto: regenera, con otra huella.
        assert_ne!(primera.fingerprint, segunda.fingerprint);

        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }

    #[test]
    fn el_blob_ida_y_vuelta_recupera_el_par() {
        let (cert, key) = generate().unwrap();
        let blob = encode(&cert, &key);
        let (cert2, key2) = decode(&blob).expect("un blob bien formado se decodifica");
        assert_eq!(cert2, cert);
        assert_eq!(&key2[..], &key[..]);
    }

    #[test]
    fn un_blob_truncado_no_decodifica() {
        let (cert, key) = generate().unwrap();
        let blob = encode(&cert, &key);
        // Cortado dentro del certificado: el largo anunciado no entra → None.
        assert!(decode(&blob[..6]).is_none());
        // Sin siquiera la cabecera de largo.
        assert!(decode(b"xy").is_none());
    }
}
