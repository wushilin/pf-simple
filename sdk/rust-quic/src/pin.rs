//! The QUIC connection's settings (PROTOCOL.md §13.3, §13.6): QUIC version
//! 1, TLS 1.3 with ALPN `pf-tunnel`, the hub's certificate pinned by the
//! fingerprints discovery announced, no 0-RTT and no resumption, keepalive
//! and the idle timeout.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::wire::ALPN;

/// The transport parameter `max_idle_timeout` (§13.6).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Each end sends a PING after this long without hearing anything (§13.6).
pub const KEEP_ALIVE: Duration = Duration::from_secs(10);
/// The bidirectional streams this end allows the hub (§13.3).
pub const MAX_STREAMS: u32 = 1000;
/// Each stream's receive window, and the connection's (§13.3): the
/// connection's is 16 times the stream's.
pub const STREAM_WINDOW: u32 = 1 << 20;
pub const CONN_WINDOW: u32 = 16 << 20;

/// The lowercase hex SHA-256 of a certificate's DER encoding.
pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Accepts the hub's certificate if and only if the SHA-256 of its leaf's
/// DER encoding is one of the pins. Only the chain, the name and the dates
/// go unchecked: the handshake's signature is verified with the pinned
/// certificate's key, as usual.
#[derive(Debug)]
pub(crate) struct Pin {
    pins: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
    /// Set when the hub presented a certificate that is not pinned.
    pub(crate) mismatch: Arc<AtomicBool>,
}

impl Pin {
    pub(crate) fn new(pins: Vec<[u8; 32]>) -> Pin {
        Pin { pins, provider: Arc::new(rustls::crypto::ring::default_provider()), mismatch: Arc::default() }
    }
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let sum: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&sum) {
            return Ok(ServerCertVerified::assertion());
        }
        self.mismatch.store(true, Ordering::Release);
        Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only.
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The TLS configuration for one handshake with the hub's QUIC listener.
pub(crate) fn tls_config(pin: Arc<Pin>) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(pin)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    // No resumption and no early data: every handshake is a full one and
    // shows the certificate to be pinned (§13.3). rustls sends no SNI for
    // an IP address.
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    Ok(cfg)
}

/// The QUIC configuration for one connection to the hub.
pub(crate) fn quic_config(pin: Arc<Pin>) -> Result<quinn::ClientConfig, String> {
    let tls = tls_config(pin).map_err(|e| e.to_string())?;
    let crypto = QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("30s is a valid idle timeout")))
        .keep_alive_interval(Some(KEEP_ALIVE))
        .max_concurrent_bidi_streams(MAX_STREAMS.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(STREAM_WINDOW.into())
        .receive_window(CONN_WINDOW.into())
        .datagram_receive_buffer_size(None);
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(Arc::new(transport));
    cfg.version(1); // QUIC version 1 (RFC 9000), and nothing else
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> CertificateDer<'static> {
        let c = rcgen::generate_simple_self_signed(vec!["hub.example".into()]).unwrap();
        c.cert.der().clone()
    }

    #[test]
    fn pins_the_leaf_only() {
        let leaf = cert();
        let other = cert();
        let sum: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        assert_eq!(fingerprint(leaf.as_ref()), hex::encode(sum));
        let pin = Pin::new(vec![[0u8; 32], sum]);
        let name = ServerName::try_from("anything.example").unwrap();
        // The name, the chain and the dates are not checked.
        assert!(pin.verify_server_cert(&leaf, &[], &name, &[], UnixTime::since_unix_epoch(Duration::ZERO)).is_ok());
        assert!(!pin.mismatch.load(Ordering::Acquire));
        assert!(pin.verify_server_cert(&other, std::slice::from_ref(&leaf), &name, &[], UnixTime::now()).is_err());
        assert!(pin.mismatch.load(Ordering::Acquire));
    }

    #[test]
    fn configs_are_tls13_without_resumption() {
        let pin = Arc::new(Pin::new(vec![[1u8; 32]]));
        let cfg = tls_config(pin.clone()).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"pf-tunnel".to_vec()]);
        assert!(!cfg.enable_early_data);
        assert!(quic_config(pin).is_ok());
    }
}
