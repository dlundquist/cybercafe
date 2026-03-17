/// TLS/SSL version detected from the first data packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TlsVersion {
    SslV2,
    SslV3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown,
}

impl TlsVersion {
    /// Human-readable name for error page display.
    pub fn display_name(&self) -> &'static str {
        match self {
            TlsVersion::SslV2 => "SSL 2.0",
            TlsVersion::SslV3 => "SSL 3.0",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
            TlsVersion::Unknown => "Unknown",
        }
    }

    /// True if this version is considered legacy (should be intercepted).
    pub fn is_legacy(&self) -> bool {
        matches!(self, TlsVersion::SslV2 | TlsVersion::SslV3 | TlsVersion::Tls10 | TlsVersion::Tls11)
    }

    /// True if this version is modern (should pass through).
    pub fn is_modern(&self) -> bool {
        matches!(self, TlsVersion::Tls12 | TlsVersion::Tls13)
    }
}

/// Parse the TLS record header from a TCP payload to determine the
/// protocol version the client is advertising.
///
/// For TLS 3.x records: byte[0] = content type (0x16 = Handshake),
/// bytes[1..3] = protocol version (major.minor).
///
/// For SSLv2: the first byte has the high bit set (0x80), with the
/// version at bytes[3..5].
pub fn parse_tls_version(data: &[u8]) -> TlsVersion {
    if data.is_empty() {
        return TlsVersion::Unknown;
    }

    // SSLv2 record format: first byte has high bit set
    if data[0] & 0x80 != 0 && data.len() >= 5 {
        // SSLv2 ClientHello: bytes[3..5] contain version
        let major = data[3];
        let minor = data[4];
        return match (major, minor) {
            (2, _) => TlsVersion::SslV2,
            (3, 0) => TlsVersion::SslV3,
            (3, 1) => TlsVersion::Tls10,
            (3, 2) => TlsVersion::Tls11,
            (3, 3) => TlsVersion::Tls12,
            _ => TlsVersion::Unknown,
        };
    }

    // TLS record: byte[0] = content type, bytes[1..3] = version
    if data.len() < 3 {
        return TlsVersion::Unknown;
    }

    // Content type 0x16 = Handshake
    if data[0] != 0x16 {
        return TlsVersion::Unknown;
    }

    let major = data[1];
    let minor = data[2];
    match (major, minor) {
        (3, 0) => TlsVersion::SslV3,
        (3, 1) => TlsVersion::Tls10,
        (3, 2) => TlsVersion::Tls11,
        // TLS 1.3 ClientHello uses 0x0303 in the record layer
        // (the actual version is in the supported_versions extension)
        (3, 3) => TlsVersion::Tls12,
        _ => TlsVersion::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls12_handshake() {
        // TLS 1.2 ClientHello record header
        let data = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(parse_tls_version(&data), TlsVersion::Tls12);
        assert!(TlsVersion::Tls12.is_modern());
        assert!(!TlsVersion::Tls12.is_legacy());
    }

    #[test]
    fn test_tls11_handshake() {
        let data = [0x16, 0x03, 0x02, 0x00, 0x05];
        assert_eq!(parse_tls_version(&data), TlsVersion::Tls11);
        assert!(TlsVersion::Tls11.is_legacy());
    }

    #[test]
    fn test_tls10_handshake() {
        let data = [0x16, 0x03, 0x01, 0x00, 0x05];
        assert_eq!(parse_tls_version(&data), TlsVersion::Tls10);
        assert!(TlsVersion::Tls10.is_legacy());
    }

    #[test]
    fn test_sslv3_handshake() {
        let data = [0x16, 0x03, 0x00, 0x00, 0x05];
        assert_eq!(parse_tls_version(&data), TlsVersion::SslV3);
        assert!(TlsVersion::SslV3.is_legacy());
    }

    #[test]
    fn test_sslv2_clienthello() {
        // SSLv2 format: high bit set, then length, then msg type, then version
        let data = [0x80, 0x2e, 0x01, 0x02, 0x00];
        assert_eq!(parse_tls_version(&data), TlsVersion::SslV2);
        assert!(TlsVersion::SslV2.is_legacy());
    }

    #[test]
    fn test_sslv2_with_tls10_version() {
        // SSLv2 record wrapping a TLS 1.0 ClientHello
        let data = [0x80, 0x2e, 0x01, 0x03, 0x01];
        assert_eq!(parse_tls_version(&data), TlsVersion::Tls10);
    }

    #[test]
    fn test_non_tls() {
        let data = [0x47, 0x45, 0x54, 0x20, 0x2f]; // "GET /"
        assert_eq!(parse_tls_version(&data), TlsVersion::Unknown);
    }

    #[test]
    fn test_empty() {
        assert_eq!(parse_tls_version(&[]), TlsVersion::Unknown);
    }

    #[test]
    fn test_too_short() {
        assert_eq!(parse_tls_version(&[0x16, 0x03]), TlsVersion::Unknown);
    }

    #[test]
    fn test_display_names() {
        assert_eq!(TlsVersion::SslV2.display_name(), "SSL 2.0");
        assert_eq!(TlsVersion::SslV3.display_name(), "SSL 3.0");
        assert_eq!(TlsVersion::Tls10.display_name(), "TLS 1.0");
        assert_eq!(TlsVersion::Tls11.display_name(), "TLS 1.1");
        assert_eq!(TlsVersion::Tls12.display_name(), "TLS 1.2");
        assert_eq!(TlsVersion::Tls13.display_name(), "TLS 1.3");
    }
}
