//! Policy routing setup via NETLINK_ROUTE using the mnl crate.
//!
//! Sets up:
//! - `ip rule add fwmark <mark> lookup <table>`
//! - `ip route add local 0.0.0.0/0 dev lo table <table>`

use std::io;

use mnl::{flags, fra, rta, rtm, MnlMsg, MnlSocket};

/// rtmsg struct (from linux/rtnetlink.h)
#[repr(C)]
struct Rtmsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

// Route types
const RTN_LOCAL: u8 = 2;

// Route protocols
const RTPROT_BOOT: u8 = 3;

// Route scopes
const RT_SCOPE_HOST: u8 = 254;

/// fib_rule_hdr struct (from linux/fib_rules.h)
#[repr(C)]
struct FibRuleHdr {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    res1: u8,
    res2: u8,
    action: u8,
    flags: u32,
}

// FIB rule actions
const FR_ACT_TO_TBL: u8 = 1;

/// Add policy routing: fwmark → table lookup + local default route in table.
pub fn add_policy_routing(mark: u32, table: u32) -> io::Result<()> {
    let sock = MnlSocket::open(libc::NETLINK_ROUTE)?;
    sock.bind(0, 0)?;

    // 1. ip rule add fwmark <mark> lookup <table>
    let mut msg = MnlMsg::new(
        rtm::RTM_NEWRULE,
        flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_EXCL,
        1,
    );
    let hdr: &mut FibRuleHdr = msg.put_extra_header();
    hdr.family = libc::AF_INET as u8;
    hdr.action = FR_ACT_TO_TBL;
    hdr.table = if table < 256 { table as u8 } else { 0 };
    msg.put_u32(fra::FRA_FWMARK, mark);
    if table >= 256 {
        msg.put_u32(fra::FRA_TABLE, table);
    }
    sock.send_recv_ack(&msg)?;

    // 2. ip route add local 0.0.0.0/0 dev lo table <table>
    let lo_idx = mnl::if_nametoindex("lo")?;
    let mut msg = MnlMsg::new(
        rtm::RTM_NEWROUTE,
        flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_EXCL,
        2,
    );
    let rt: &mut Rtmsg = msg.put_extra_header();
    rt.rtm_family = libc::AF_INET as u8;
    rt.rtm_dst_len = 0; // 0.0.0.0/0
    rt.rtm_table = if table < 256 { table as u8 } else { 0 };
    rt.rtm_type = RTN_LOCAL;
    rt.rtm_protocol = RTPROT_BOOT;
    rt.rtm_scope = RT_SCOPE_HOST;
    msg.put_u32(rta::RTA_OIF, lo_idx as u32);
    if table >= 256 {
        msg.put_u32(rta::RTA_TABLE, table);
    }
    // Destination 0.0.0.0
    msg.put(rta::RTA_DST, &[0u8; 4]);
    sock.send_recv_ack(&msg)?;

    log::info!(
        "policy routing: fwmark 0x{:x} → table {}, local 0.0.0.0/0 dev lo",
        mark,
        table
    );
    Ok(())
}

/// Remove policy routing rules.
pub fn del_policy_routing(mark: u32, table: u32) -> io::Result<()> {
    let sock = MnlSocket::open(libc::NETLINK_ROUTE)?;
    sock.bind(0, 0)?;

    // Delete rule
    let mut msg = MnlMsg::new(
        rtm::RTM_DELRULE,
        flags::NLM_F_REQUEST | flags::NLM_F_ACK,
        1,
    );
    let hdr: &mut FibRuleHdr = msg.put_extra_header();
    hdr.family = libc::AF_INET as u8;
    hdr.action = FR_ACT_TO_TBL;
    hdr.table = if table < 256 { table as u8 } else { 0 };
    msg.put_u32(fra::FRA_FWMARK, mark);
    if table >= 256 {
        msg.put_u32(fra::FRA_TABLE, table);
    }
    // Best effort — ignore ENOENT
    match sock.send_recv_ack(&msg) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => return Err(e),
    }

    // Delete route
    let lo_idx = mnl::if_nametoindex("lo")?;
    let mut msg = MnlMsg::new(
        rtm::RTM_DELROUTE,
        flags::NLM_F_REQUEST | flags::NLM_F_ACK,
        2,
    );
    let rt: &mut Rtmsg = msg.put_extra_header();
    rt.rtm_family = libc::AF_INET as u8;
    rt.rtm_dst_len = 0;
    rt.rtm_table = if table < 256 { table as u8 } else { 0 };
    rt.rtm_type = RTN_LOCAL;
    rt.rtm_scope = RT_SCOPE_HOST;
    msg.put_u32(rta::RTA_OIF, lo_idx as u32);
    if table >= 256 {
        msg.put_u32(rta::RTA_TABLE, table);
    }
    msg.put(rta::RTA_DST, &[0u8; 4]);
    match sock.send_recv_ack(&msg) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => return Err(e),
    }

    log::info!(
        "policy routing: removed fwmark 0x{:x} / table {}",
        mark,
        table
    );
    Ok(())
}
