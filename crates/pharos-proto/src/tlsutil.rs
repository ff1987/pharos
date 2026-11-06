use std::fs;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig};

use crate::error::ProtoError;

/// ALPN for both QUIC and TLS. Mismatch fails the handshake.
pub const ALPN: &[u8] = b"pharos/1";

/// Certificate plus private key, kept as PEM so a dev server can publish the cert.
pub struct Identity {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub cert_pem: String,
    pub key_pem: String,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
        }
    }
}

pub fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn generate_dev_identity() -> Result<Identity, ProtoError> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let signing_key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&signing_key)?;
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let cert_der = cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    Ok(Identity {
        certs: vec![cert_der],
        key,
        cert_pem,
        key_pem,
    })
}

pub fn identity_from_pem(cert_pem: &str, key_pem: &str) -> Result<Identity, ProtoError> {
    let certs = certs_from_pem(cert_pem)?;
    if certs.is_empty() {
        return Err(ProtoError::Cert("no certificates in PEM".into()));
    }
    let key = key_from_pem(key_pem)?;
    Ok(Identity {
        certs,
        key,
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
    })
}

pub fn identity_from_files(cert_path: &Path, key_path: &Path) -> Result<Identity, ProtoError> {
    let cert_pem = fs::read_to_string(cert_path)
        .map_err(|err| ProtoError::Cert(format!("read {}: {err}", cert_path.display())))?;
    let key_pem = fs::read_to_string(key_path)
        .map_err(|err| ProtoError::Cert(format!("read {}: {err}", key_path.display())))?;
    identity_from_pem(&cert_pem, &key_pem)
}

pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, ProtoError> {
    let mut cursor = Cursor::new(pem.as_bytes());
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ProtoError::Cert(format!("parse certificate pem: {err}")))
}

pub fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, ProtoError> {
    let mut cursor = Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|err| ProtoError::Cert(format!("parse private key pem: {err}")))?
        .ok_or_else(|| ProtoError::Cert("no private key in PEM".into()))
}

pub fn server_config(
    identity: &Identity,
    client_ca_pem: Option<&str>,
) -> Result<ServerConfig, ProtoError> {
    install_ring();
    let builder = ServerConfig::builder();
    let builder = if let Some(pem) = client_ca_pem {
        let mut roots = RootCertStore::empty();
        for cert in certs_from_pem(pem)? {
            roots
                .add(cert)
                .map_err(|err| ProtoError::Cert(format!("client trust anchor: {err}")))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|err| ProtoError::Tls(err.to_string()))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_single_cert(identity.certs.clone(), identity.key.clone_key())?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

pub fn client_config_with_ca(
    ca_pem: &str,
    client: Option<&Identity>,
) -> Result<ClientConfig, ProtoError> {
    install_ring();
    let mut roots = RootCertStore::empty();
    for cert in certs_from_pem(ca_pem)? {
        roots
            .add(cert)
            .map_err(|err| ProtoError::Cert(format!("trust anchor: {err}")))?;
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    finish_client(builder, client)
}

pub fn client_config_insecure(client: Option<&Identity>) -> Result<ClientConfig, ProtoError> {
    install_ring();
    let builder = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new());
    finish_client(builder, client)
}

fn finish_client(
    builder: rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
    client: Option<&Identity>,
) -> Result<ClientConfig, ProtoError> {
    let mut config = match client {
        Some(identity) => builder
            .with_client_auth_cert(identity.certs.clone(), identity.key.clone_key())
            .map_err(|err| ProtoError::Tls(err.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

/// A client certificate and the CA that signed it.
pub struct IssuedClient {
    pub ca_pem: String,
    pub identity: Identity,
}

/// Mint a lab client CA and one client certificate with the clientAuth EKU.
pub fn issue_client_certificate() -> Result<IssuedClient, ProtoError> {
    let ca_key = rcgen::KeyPair::generate()?;
    let mut ca_params = rcgen::CertificateParams::new(vec!["Pharos Client CA".into()])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.clone().self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let client_key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec!["pharos-client".into()])?;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let cert = params.signed_by(&client_key, &issuer)?;
    let identity = Identity {
        certs: vec![cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        cert_pem: cert.pem(),
        key_pem: client_key.serialize_pem(),
    };
    Ok(IssuedClient {
        ca_pem: ca_cert.pem(),
        identity,
    })
}

pub fn server_name(name: &str) -> Result<ServerName<'static>, ProtoError> {
    ServerName::try_from(name.to_string()).map_err(|err| ProtoError::Tls(err.to_string()))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
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
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
