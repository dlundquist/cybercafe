//! Certificate minting for legacy TLS interception.
//!
//! Generates an ephemeral CA at startup and mints per-connection RSA-1024
//! end-entity certificates matching the real server's CN and SANs.

use std::io;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};

/// A CA key pair for signing minted certificates.
pub struct CaKeyPair {
    pub key: PKey<Private>,
    pub cert: X509,
}

/// LRU cache of minted (cert, key) pairs keyed by (hostname, port).
///
/// Avoids re-fetching the upstream certificate and re-generating an RSA key
/// for every connection to the same server.  The default capacity (256) keeps
/// memory usage well under 1 MB on a Raspberry Pi.
pub struct CertCache {
    inner: Mutex<LruCache<(String, u16), (X509, PKey<Private>)>>,
}

impl CertCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("cert cache capacity must be > 0"),
            )),
        }
    }

    /// Return a cached (cert, key) clone, or `None` on miss.
    pub fn get(&self, host: &str, port: u16) -> Option<(X509, PKey<Private>)> {
        self.inner
            .lock()
            .unwrap()
            .get(&(host.to_string(), port))
            .map(|(c, k)| (c.clone(), k.clone()))
    }

    /// Insert a (cert, key) pair into the cache.
    pub fn put(&self, host: String, port: u16, cert: X509, key: PKey<Private>) {
        self.inner
            .lock()
            .unwrap()
            .put((host, port), (cert, key));
    }
}

/// Generate an ephemeral CA key pair (RSA-2048, self-signed, 10-year validity).
pub fn generate_ephemeral_ca() -> Result<CaKeyPair, openssl::error::ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, "tls-guard Ephemeral CA")?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "tls-guard")?;
    let name = name_builder.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?; // X.509 v3

    let serial = BigNum::from_u32(1)?;
    let serial_asn1 = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial_asn1)?;

    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?; // ~10 years
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;

    builder.sign(&key, MessageDigest::sha256())?;
    let cert = builder.build();

    Ok(CaKeyPair { key, cert })
}

/// Load a CA key pair from PEM files.
pub fn load_ca(key_path: &str, cert_path: &str) -> io::Result<CaKeyPair> {
    let key_pem = std::fs::read(key_path)?;
    let cert_pem = std::fs::read(cert_path)?;

    let key = PKey::private_key_from_pem(&key_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let cert = X509::from_pem(&cert_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(CaKeyPair { key, cert })
}

/// Mint an end-entity certificate with RSA-1024, signed by the given CA.
pub fn mint_cert(
    ca: &CaKeyPair,
    cn: &str,
    sans: &[String],
) -> Result<(X509, PKey<Private>), openssl::error::ErrorStack> {
    let rsa = Rsa::generate(1024)?;
    let key = PKey::from_rsa(rsa)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let subject = name_builder.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;

    let serial = {
        let mut bn = BigNum::new()?;
        bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
        bn.to_asn1_integer()?
    };
    builder.set_serial_number(&serial)?;

    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(ca.cert.subject_name())?;
    builder.set_pubkey(&key)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(1)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Build SAN extension
    if !sans.is_empty() {
        let mut san_builder = SubjectAlternativeName::new();
        for name in sans {
            // Try parsing as IP, otherwise treat as DNS name
            if name.parse::<IpAddr>().is_ok() {
                san_builder.ip(name);
            } else {
                san_builder.dns(name);
            }
        }
        let san_ext = san_builder.build(&builder.x509v3_context(Some(&ca.cert), None))?;
        builder.append_extension(san_ext)?;
    }

    builder.sign(&ca.key, MessageDigest::sha256())?;
    let cert = builder.build();

    Ok((cert, key))
}

/// Fetch the CN and SANs from a remote server's certificate.
pub fn fetch_server_cert_info(
    host: &str,
    port: u16,
) -> io::Result<(String, Vec<String>)> {
    let mut connector_builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // We don't care about verification — we just want the cert
    connector_builder.set_verify(SslVerifyMode::NONE);
    let connector = connector_builder.build();

    let addr = format!("{}:{}", host, port);
    let stream = std::net::TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    let ssl_stream = connector
        .connect(host, stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let peer_cert = ssl_stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no peer certificate"))?;

    let cn = peer_cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| host.to_string());

    let mut sans = Vec::new();
    if let Some(alt_names) = peer_cert.subject_alt_names() {
        for name in alt_names {
            if let Some(dns) = name.dnsname() {
                sans.push(dns.to_string());
            } else if let Some(ip) = name.ipaddress() {
                // ipaddress() returns raw bytes
                if ip.len() == 4 {
                    let addr = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                    sans.push(addr.to_string());
                } else if ip.len() == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(ip);
                    let addr = std::net::Ipv6Addr::from(octets);
                    sans.push(addr.to_string());
                }
            }
        }
    }

    Ok((cn, sans))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ephemeral_ca() {
        let ca = generate_ephemeral_ca().unwrap();

        // Check that it's a CA cert
        let cn = ca
            .cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(cn.to_string(), "tls-guard Ephemeral CA");
    }

    #[test]
    fn test_mint_cert() {
        let ca = generate_ephemeral_ca().unwrap();

        let sans = vec!["example.com".to_string(), "www.example.com".to_string()];
        let (cert, _key) = mint_cert(&ca, "example.com", &sans).unwrap();

        // Check CN
        let cn = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(cn.to_string(), "example.com");

        // Check issuer
        let issuer_cn = cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(issuer_cn.to_string(), "tls-guard Ephemeral CA");

        // Check SANs
        let alt_names = cert.subject_alt_names().unwrap();
        let dns_names: Vec<&str> = alt_names.iter().filter_map(|n| n.dnsname()).collect();
        assert!(dns_names.contains(&"example.com"));
        assert!(dns_names.contains(&"www.example.com"));
    }

    #[test]
    fn test_mint_cert_with_ip_san() {
        let ca = generate_ephemeral_ca().unwrap();
        let sans = vec!["192.168.1.1".to_string()];
        let (cert, _key) = mint_cert(&ca, "test.local", &sans).unwrap();

        let alt_names = cert.subject_alt_names().unwrap();
        // Should have an IP SAN
        assert!(alt_names.iter().any(|n| n.ipaddress().is_some()));
    }
}
