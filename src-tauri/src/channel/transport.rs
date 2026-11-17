//! El transporte del lado del teléfono: TLS mutuo con certificados autofirmados
//! y fijados, y el enmarcado de los mensajes sobre él.
//!
//! Es el espejo cliente de `daemon/src/channel/transport.rs`. No hay CA, así que
//! el verificador acepta cualquier certificado de servidor y deja la confianza
//! para después del handshake, donde se compara la huella contra la fijada en el
//! pareo. Lo que el verificador **sí** hace es comprobar la firma del handshake
//! contra la clave del certificado presentado: eso prueba que el otro lado tiene
//! la clave privada. Saltarse la cadena no es saltarse la prueba de posesión.
//!
//! El enmarcado (largo delante, tope de tamaño, decodificación) es puro y vive en
//! `vasak_connect_protocol::pure`; acá sólo se mueven bytes sobre el socket.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use vasak_connect_protocol::pure::{
    check_frame_len, decode_frame, encode_frame, fingerprint_from_der, frame_len, FrameError,
};
use vasak_connect_protocol::wire::Message;

use super::identity::Identity;

/// El proveedor criptográfico: `ring`, el mismo que el daemon, elegido explícito
/// para no arrastrar `aws-lc-sys` (que pide `cmake`) ni depender de un proveedor
/// global.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Verificador del certificado del servidor (el escritorio). Acepta cualquiera
/// —el pinning es posterior al handshake— pero verifica la firma con la clave del
/// certificado presentado.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// La configuración de cliente: presenta nuestra identidad (TLS mutuo) y acepta
/// la del servidor para fijarla después.
fn client_config(identity: &Identity) -> Result<ClientConfig, rustls::Error> {
    let provider = provider();
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
        .with_client_auth_cert(
            vec![identity.cert_der.clone()],
            identity.key_der.clone_key(),
        )
}

/// Un error de la sesión: de red, de enmarcado, de TLS o de cierre limpio.
#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    Tls(rustls::Error),
    Frame(FrameError),
    /// El otro lado cerró la conexión entre marcos.
    Closed,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Io(err) => write!(f, "{err}"),
            SessionError::Tls(err) => write!(f, "TLS: {err}"),
            SessionError::Frame(err) => write!(f, "{err}"),
            SessionError::Closed => write!(f, "el escritorio cerró la conexión"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(err: std::io::Error) -> Self {
        SessionError::Io(err)
    }
}

/// Una sesión TLS abierta con un escritorio, más la huella del certificado que
/// presentó (ya calculada, para fijarla o compararla sin bajar al TLS).
pub struct Session {
    stream: TlsStream<TcpStream>,
    peer_fingerprint: String,
}

impl Session {
    /// La huella SHA-256 del certificado del escritorio, con dos puntos.
    pub fn peer_fingerprint(&self) -> &str {
        &self.peer_fingerprint
    }

    /// Abre un TCP a `addr`, hace el handshake TLS mutuo presentando `identity`, y
    /// saca la huella del certificado del escritorio. El nombre de servidor es
    /// irrelevante (no hay validación de nombre), pero rustls exige uno válido.
    pub async fn connect(addr: SocketAddr, identity: &Identity) -> Result<Session, SessionError> {
        let config = client_config(identity).map_err(SessionError::Tls)?;
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(addr).await?;
        // Un nombre fijo y válido: el verificador lo ignora, el pinning va por la
        // huella del certificado.
        let server_name = ServerName::try_from("vasak-connect")
            .expect("«vasak-connect» es un nombre de servidor válido");
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(SessionError::Io)?;

        let peer_fingerprint = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(<[_]>::first)
            .map(|cert| fingerprint_from_der(cert))
            .ok_or_else(|| {
                SessionError::Tls(rustls::Error::General(
                    "el escritorio no presentó certificado".into(),
                ))
            })?;

        Ok(Session {
            stream,
            peer_fingerprint,
        })
    }

    /// Lee un marco completo: la cabecera de largo, el chequeo de tamaño (que
    /// rechaza un largo enorme antes de reservar) y el cuerpo.
    pub async fn read(&mut self) -> Result<Message, SessionError> {
        let mut header = [0u8; 4];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(SessionError::Closed)
            }
            Err(err) => return Err(SessionError::Io(err)),
        }
        let len = check_frame_len(frame_len(header)).map_err(SessionError::Frame)?;
        let mut body = vec![0u8; len];
        self.stream
            .read_exact(&mut body)
            .await
            .map_err(SessionError::Io)?;
        decode_frame(&body).map_err(SessionError::Frame)
    }

    /// Escribe un marco y hace `flush` para que salga ya.
    pub async fn write(&mut self, message: &Message) -> Result<(), SessionError> {
        self.stream
            .write_all(&encode_frame(message))
            .await
            .map_err(SessionError::Io)?;
        self.stream.flush().await.map_err(SessionError::Io)
    }
}
