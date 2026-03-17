//! DNS response sniffer: captures UDP/53 responses on the guarded interface
//! and maintains an IP→hostname map for cert CN/SAN generation.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::unix::AsyncFd;

/// An entry in the DNS snoop cache.
struct DnsEntry {
    hostname: String,
    expires: Instant,
}

/// Thread-safe DNS snoop map: resolved IP address → hostname.
pub struct DnsSnoopMap {
    inner: DashMap<IpAddr, DnsEntry>,
}

impl DnsSnoopMap {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Look up a hostname for the given IP. Returns None if not found or expired.
    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let entry = self.inner.get(ip)?;
        if Instant::now() > entry.expires {
            drop(entry);
            self.inner.remove(ip);
            return None;
        }
        Some(entry.hostname.clone())
    }

    /// Insert or update an entry with a TTL.
    fn insert(&self, ip: IpAddr, hostname: String, ttl_secs: u32) {
        let ttl = ttl_secs.max(60); // minimum 60s to avoid thrashing
        self.inner.insert(
            ip,
            DnsEntry {
                hostname,
                expires: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );
    }
}

/// Parse a DNS response packet (starting after UDP header) and extract
/// A/AAAA answer records into the snoop map.
pub fn parse_dns_response(data: &[u8], map: &DnsSnoopMap) -> usize {
    if data.len() < 12 {
        return 0;
    }

    // Check QR bit (response)
    if data[2] & 0x80 == 0 {
        return 0; // query, not response
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if ancount == 0 {
        return 0;
    }

    // Skip question section
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos);
        if pos == 0 || pos + 4 > data.len() {
            return 0;
        }
        pos += 4; // QTYPE + QCLASS
    }

    // Extract the query name from the first question for hostname lookup
    let qname = read_dns_name(data, 12);

    let mut count = 0;
    // Parse answer section
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        // Skip the name in the answer
        let name_end = skip_dns_name(data, pos);
        if name_end == 0 || name_end + 10 > data.len() {
            break;
        }
        pos = name_end;

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        if let Some(ref hostname) = qname {
            match rtype {
                1 if rdlength == 4 => {
                    // A record
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ));
                    map.insert(ip, hostname.clone(), ttl);
                    count += 1;
                }
                28 if rdlength == 16 => {
                    // AAAA record
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[pos..pos + 16]);
                    let ip = IpAddr::V6(Ipv6Addr::from(octets));
                    map.insert(ip, hostname.clone(), ttl);
                    count += 1;
                }
                _ => {}
            }
        }

        pos += rdlength;
    }

    count
}

/// Skip a DNS name (handles compression pointers).
fn skip_dns_name(data: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= data.len() {
            return 0;
        }
        let len = data[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total
            return pos + 2;
        }
        pos += 1 + len;
    }
}

/// Read a DNS name, resolving compression pointers, into a dotted string.
fn read_dns_name(data: &[u8], mut pos: usize) -> Option<String> {
    let mut name = String::new();
    let mut jumps = 0;

    loop {
        if pos >= data.len() || jumps > 10 {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let offset = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            pos = offset;
            jumps += 1;
            continue;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Create and bind an AF_PACKET socket with BPF filter for DNS responses.
fn create_dns_socket(if_index: i32) -> io::Result<i32> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Bind to the specific interface
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    addr.sll_ifindex = if_index;

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as u32,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // BPF filter: accept only UDP src port 53
    let bpf_insns: [libc::sock_filter; 6] = [
        // ldb [9] — IP protocol
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 9 },
        // jeq #17 (UDP) — if not, jump to reject
        libc::sock_filter { code: 0x15, jt: 0, jf: 3, k: 17 },
        // ldh [20] — UDP src port (offset 20 assuming IHL=5)
        libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 20 },
        // jeq #53 — if not, reject
        libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 53 },
        // accept
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
        // reject
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
    ];

    let bpf_prog = libc::sock_fprog {
        len: bpf_insns.len() as u16,
        filter: bpf_insns.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &bpf_prog as *const _ as *const libc::c_void,
            std::mem::size_of_val(&bpf_prog) as u32,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(fd)
}

/// Create and bind the DNS capture socket (requires CAP_NET_RAW).
///
/// Call this during privileged startup, then pass the fd to
/// [`run_dns_snooper`] after dropping privileges.
pub fn bind_dns_socket(iface: &str) -> io::Result<i32> {
    let if_index = mnl::if_nametoindex(iface)?;
    let fd = create_dns_socket(if_index)?;
    log::info!("DNS snooper: bound on {}", iface);
    Ok(fd)
}

/// Run the DNS snooper recv loop (no privileges required).
///
/// Takes a pre-bound fd from [`bind_dns_socket`].
pub async fn run_dns_snooper(fd: i32, map: Arc<DnsSnoopMap>) -> io::Result<()> {
    log::info!("DNS snooper: processing packets");

    let async_fd = AsyncFd::new(fd)?;
    let mut buf = vec![0u8; 65536];

    loop {
        let mut guard = async_fd.readable().await?;

        let n = unsafe {
            libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(err);
        }

        if n > 0 {
            let pkt = &buf[..n as usize];
            // Parse IP header to find UDP payload
            if pkt.len() >= 28 {
                let ihl = ((pkt[0] & 0x0F) as usize) * 4;
                if pkt.len() >= ihl + 8 {
                    let udp_payload = &pkt[ihl + 8..];
                    let count = parse_dns_response(udp_payload, &map);
                    if count > 0 {
                        log::debug!("DNS snooper: cached {} records", count);
                    }
                }
            }
        }

        guard.clear_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_response(name: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Transaction ID
        pkt.extend_from_slice(&[0x12, 0x34]);
        // Flags: QR=1, standard response
        pkt.extend_from_slice(&[0x81, 0x80]);
        // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x01]);
        // ANCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x01]);
        // NSCOUNT=0, ARCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Question section: encode name
        let qname_start = pkt.len();
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root label
        // QTYPE=A, QCLASS=IN
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer section: compression pointer to question name
        pkt.push(0xC0);
        pkt.push(qname_start as u8);
        // TYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]);
        // CLASS=IN
        pkt.extend_from_slice(&[0x00, 0x01]);
        // TTL
        pkt.extend_from_slice(&ttl.to_be_bytes());
        // RDLENGTH=4
        pkt.extend_from_slice(&[0x00, 0x04]);
        // RDATA
        pkt.extend_from_slice(&ip);

        pkt
    }

    #[test]
    fn test_parse_dns_response_a_record() {
        let pkt = build_dns_response("example.com", [93, 184, 216, 34], 300);
        let map = DnsSnoopMap::new();

        let count = parse_dns_response(&pkt, &map);
        assert_eq!(count, 1);

        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(map.lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_dns_response_not_response() {
        let mut pkt = build_dns_response("example.com", [1, 2, 3, 4], 300);
        // Clear QR bit
        pkt[2] &= !0x80;

        let map = DnsSnoopMap::new();
        assert_eq!(parse_dns_response(&pkt, &map), 0);
    }

    #[test]
    fn test_dns_name_parsing() {
        // Build a name: 7example3com0
        let data = b"\x07example\x03com\x00";
        let name = read_dns_name(data, 0);
        assert_eq!(name, Some("example.com".to_string()));
    }

    #[test]
    fn test_dns_name_with_compression() {
        // Name at offset 0: 7example3com0
        // Pointer at offset 13: C0 00 (points to offset 0)
        let mut data = vec![];
        data.extend_from_slice(b"\x07example\x03com\x00");
        data.extend_from_slice(&[0xC0, 0x00]);

        let name = read_dns_name(&data, 13);
        assert_eq!(name, Some("example.com".to_string()));
    }

    #[test]
    fn test_snoop_map_ttl_expiry() {
        let map = DnsSnoopMap::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Insert with 0 TTL (will be clamped to 60s minimum)
        map.insert(ip, "test.com".to_string(), 0);
        assert!(map.lookup(&ip).is_some());
    }
}
