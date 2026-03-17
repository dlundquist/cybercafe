//! Config file parser for port rules.
//!
//! Each line: `<port> <mode> [<upstream_port>]`
//! Modes: guard, proxy, upgrade

use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortAction {
    /// NFQUEUE classify; legacy TLS → error page
    Guard,
    /// NFQUEUE classify; legacy TLS → MITM bidirectional proxy
    Proxy,
    /// Unconditional TPROXY; plaintext → TLS to upstream port
    Upgrade { tls_port: u16 },
}

#[derive(Debug, Clone)]
pub struct PortRule {
    pub port: u16,
    pub action: PortAction,
}

/// Load port rules from a config file.
pub fn load_port_rules(path: &str) -> io::Result<Vec<PortRule>> {
    let contents = std::fs::read_to_string(path)?;
    parse_port_rules(&contents)
}

/// Parse port rules from a string (for testability).
pub fn parse_port_rules(contents: &str) -> io::Result<Vec<PortRule>> {
    let mut rules = Vec::new();
    for (lineno, raw_line) in contents.lines().enumerate() {
        // Strip inline comments
        let line = match raw_line.find('#') {
            Some(pos) => &raw_line[..pos],
            None => raw_line,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: expected '<port> <mode> [<tls_port>]'", lineno + 1),
            ));
        }

        let port: u16 = parts[0].parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: invalid port '{}'", lineno + 1, parts[0]),
            )
        })?;

        let action = match parts[1] {
            "guard" => PortAction::Guard,
            "proxy" => PortAction::Proxy,
            "upgrade" => {
                if parts.len() < 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("line {}: 'upgrade' requires <tls_port>", lineno + 1),
                    ));
                }
                let tls_port: u16 = parts[2].parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("line {}: invalid tls_port '{}'", lineno + 1, parts[2]),
                    )
                })?;
                PortAction::Upgrade { tls_port }
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: unknown mode '{}'", lineno + 1, other),
                ));
            }
        };

        // Check for duplicate ports
        if rules.iter().any(|r: &PortRule| r.port == port) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: duplicate port {}", lineno + 1, port),
            ));
        }

        rules.push(PortRule { port, action });
    }
    Ok(rules)
}

/// Ports that need NFQUEUE classification (guard or proxy).
pub fn guard_proxy_ports(rules: &[PortRule]) -> Vec<u16> {
    rules
        .iter()
        .filter(|r| matches!(r.action, PortAction::Guard | PortAction::Proxy))
        .map(|r| r.port)
        .collect()
}

/// (plaintext_port, tls_port) pairs for upgrade rules.
pub fn upgrade_rules(rules: &[PortRule]) -> Vec<(u16, u16)> {
    rules
        .iter()
        .filter_map(|r| match r.action {
            PortAction::Upgrade { tls_port } => Some((r.port, tls_port)),
            _ => None,
        })
        .collect()
}

/// Look up the action for a given port.
pub fn action_for_port<'a>(rules: &'a [PortRule], port: u16) -> Option<&'a PortAction> {
    rules.iter().find(|r| r.port == port).map(|r| &r.action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_three_modes() {
        let input = "\
443  guard
8443 proxy
110  upgrade  995
";
        let rules = parse_port_rules(input).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].port, 443);
        assert_eq!(rules[0].action, PortAction::Guard);
        assert_eq!(rules[1].port, 8443);
        assert_eq!(rules[1].action, PortAction::Proxy);
        assert_eq!(rules[2].port, 110);
        assert_eq!(rules[2].action, PortAction::Upgrade { tls_port: 995 });
    }

    #[test]
    fn parse_comments_and_blanks() {
        let input = "\
# This is a comment
443  guard              # HTTPS

  # Another comment
110  upgrade  995       # POP3
";
        let rules = parse_port_rules(input).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].port, 443);
        assert_eq!(rules[1].port, 110);
    }

    #[test]
    fn parse_empty() {
        let rules = parse_port_rules("# only comments\n\n").unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn error_duplicate_port() {
        let input = "443 guard\n443 proxy\n";
        let err = parse_port_rules(input).unwrap_err();
        assert!(err.to_string().contains("duplicate port 443"));
    }

    #[test]
    fn error_missing_tls_port() {
        let input = "110 upgrade\n";
        let err = parse_port_rules(input).unwrap_err();
        assert!(err.to_string().contains("requires <tls_port>"));
    }

    #[test]
    fn error_unknown_mode() {
        let input = "443 foobar\n";
        let err = parse_port_rules(input).unwrap_err();
        assert!(err.to_string().contains("unknown mode"));
    }

    #[test]
    fn error_invalid_port() {
        let input = "abc guard\n";
        let err = parse_port_rules(input).unwrap_err();
        assert!(err.to_string().contains("invalid port"));
    }

    #[test]
    fn helper_functions() {
        let input = "443 guard\n8443 proxy\n110 upgrade 995\n143 upgrade 993\n";
        let rules = parse_port_rules(input).unwrap();

        assert_eq!(guard_proxy_ports(&rules), vec![443, 8443]);
        assert_eq!(upgrade_rules(&rules), vec![(110, 995), (143, 993)]);
        assert_eq!(action_for_port(&rules, 443), Some(&PortAction::Guard));
        assert_eq!(action_for_port(&rules, 110), Some(&PortAction::Upgrade { tls_port: 995 }));
        assert_eq!(action_for_port(&rules, 9999), None);
    }
}
