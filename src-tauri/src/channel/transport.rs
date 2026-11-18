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
//! `vasak_connect_protocol::pure`; acá sólo se mueven bytes sobre el socket. La
//! sesión se parte en una tarea lectora y una escritora conectadas por canales
//! (`reader_loop`/`writer_loop`): así el bucle del pareo nunca cancela una lectura
//! a mitad de una trama —`read_exact` no es cancel-safe— y queda, además,
//! probable con un `duplex` en memoria, sin TLS.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
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

/// Lee un marco completo: la cabecera de largo, el chequeo de tamaño (que rechaza
/// un largo enorme ANTES de reservar) y el cuerpo. No es cancel-safe (encadena dos
/// `read_exact`), por eso corre dentro de [`reader_loop`], nunca en un `select`.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message, SessionError> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(SessionError::Closed)
        }
        Err(err) => return Err(SessionError::Io(err)),
    }
    let len = check_frame_len(frame_len(header)).map_err(SessionError::Frame)?;
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(SessionError::Io)?;
    decode_frame(&body).map_err(SessionError::Frame)
}

/// Escribe un marco y hace `flush` para que salga ya.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
) -> Result<(), SessionError> {
    writer
        .write_all(&encode_frame(message))
        .await
        .map_err(SessionError::Io)?;
    writer.flush().await.map_err(SessionError::Io)
}

/// Lee marcos de `reader` y los manda por `tx` hasta que la conexión se cierra o
/// `tx` se suelta. El primer error se reenvía y termina el bucle: el consumidor lo
/// ve y cierra la sesión. Como esta tarea es la única dueña del lector, un marco
/// nunca queda a medio leer por una cancelación.
pub async fn reader_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    tx: mpsc::Sender<Result<Message, SessionError>>,
) {
    loop {
        let message = read_frame(&mut reader).await;
        let fue_error = message.is_err();
        if tx.send(message).await.is_err() || fue_error {
            break;
        }
    }
}

/// Escribe en `writer` los marcos que llegan por `rx`, hasta que `rx` se cierra o
/// una escritura falla.
pub async fn writer_loop<W: AsyncWrite + Unpin>(mut writer: W, mut rx: mpsc::Receiver<Message>) {
    while let Some(message) = rx.recv().await {
        if write_frame(&mut writer, &message).await.is_err() {
            break;
        }
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

    /// Parte la sesión en su mitad de lectura y su mitad de escritura, para que una
    /// tarea lea y otra escriba sin pisarse.
    pub fn split(
        self,
    ) -> (
        tokio::io::ReadHalf<TlsStream<TcpStream>>,
        tokio::io::WriteHalf<TlsStream<TcpStream>>,
    ) {
        tokio::io::split(self.stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vasak_connect_protocol::pure::MAX_FRAME;

    #[tokio::test]
    async fn un_marco_escrito_se_lee_igual() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let sent = Message::Clipboard {
            text: "hola".into(),
        };
        write_frame(&mut a, &sent).await.unwrap();
        write_frame(&mut a, &Message::Ping).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), sent);
        assert_eq!(read_frame(&mut b).await.unwrap(), Message::Ping);
    }

    #[tokio::test]
    async fn un_marco_sobre_el_tope_se_rechaza_sin_leer_el_cuerpo() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let len = (MAX_FRAME as u32 + 1).to_be_bytes();
        a.write_all(&len).await.unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(SessionError::Frame(FrameError::TooLarge(_)))
        ));
    }

    #[tokio::test]
    async fn cerrar_entre_marcos_es_cierre_limpio() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(matches!(
            read_frame(&mut b).await,
            Err(SessionError::Closed)
        ));
    }

    #[tokio::test]
    async fn un_cuerpo_que_no_es_mensaje_es_error_de_marco() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0, 0, 3, b'x', b'y', b'z']).await.unwrap();
        assert!(matches!(
            read_frame(&mut b).await,
            Err(SessionError::Frame(FrameError::Malformed))
        ));
    }

    #[tokio::test]
    async fn el_lector_reenvia_los_marcos_y_corta_al_cerrarse() {
        let (mut a, b) = tokio::io::duplex(4096);
        write_frame(&mut a, &Message::Ping).await.unwrap();
        write_frame(&mut a, &Message::Pong).await.unwrap();
        drop(a); // cierra la conexión

        let (tx, mut rx) = mpsc::channel(8);
        reader_loop(b, tx).await;

        assert_eq!(rx.recv().await.unwrap().unwrap(), Message::Ping);
        assert_eq!(rx.recv().await.unwrap().unwrap(), Message::Pong);
        // El cierre llega como un error, y después el canal se cierra.
        assert!(matches!(rx.recv().await, Some(Err(SessionError::Closed))));
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn el_escritor_vuelca_lo_que_le_mandan() {
        let (a, mut b) = tokio::io::duplex(4096);
        let (tx, rx) = mpsc::channel(8);
        let writer = tokio::spawn(writer_loop(a, rx));

        tx.send(Message::Ping).await.unwrap();
        tx.send(Message::Clipboard { text: "eco".into() })
            .await
            .unwrap();
        drop(tx); // termina el writer_loop

        assert_eq!(read_frame(&mut b).await.unwrap(), Message::Ping);
        assert_eq!(
            read_frame(&mut b).await.unwrap(),
            Message::Clipboard { text: "eco".into() }
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn el_errores_de_sesion_se_explican() {
        assert!(!SessionError::Closed.to_string().is_empty());
        assert!(!SessionError::Frame(FrameError::Empty)
            .to_string()
            .is_empty());
    }
}
