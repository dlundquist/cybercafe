//! Build and apply nftables rules via NETLINK_NETFILTER using the mnl crate.
//!
//! Creates `table ip tls_guard` with a prerouting chain that:
//! 1. ACCEPTs ct mark 0x1 packets (modern TLS, fast path)
//! 2. TPROXYs ct mark 0x2 packets to the interception listener (legacy TLS)
//! 3. QUEUEs new tcp/443 connections to NFQUEUE for classification

use std::io;

use mnl::{flags, MnlBatch, MnlMsg, MnlSocket};

use crate::portmap::{self, PortRule};

// ---------------------------------------------------------------------------
// nf_tables netlink constants (from linux/netfilter/nf_tables.h)
// ---------------------------------------------------------------------------

// Subsystem
const NFNL_SUBSYS_NFTABLES: u16 = 10;

// Message types (within NFNL_SUBSYS_NFTABLES)
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 4;
const NFT_MSG_NEWRULE: u16 = 6;

fn nft_msg(msg_type: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg_type
}

// Batch markers
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFNL_SUBSYS_NONE: u16 = 0;

fn batch_msg(msg_type: u16) -> u16 {
    (NFNL_SUBSYS_NONE << 8) | msg_type
}

// Table attributes
const NFTA_TABLE_NAME: u16 = 1;

// Chain attributes
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;

// Chain hook attributes
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

// Rule attributes
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 3;

// Expression list
const NFTA_LIST_ELEM: u16 = 1;

// Expression attributes
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

// --- Expression-specific attribute constants ---

// meta
const NFTA_META_KEY: u16 = 1;
const NFTA_META_DREG: u16 = 2;
const NFTA_META_SREG: u16 = 3;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_L4PROTO: u32 = 16;
const NFT_META_MARK: u32 = 3;

// cmp
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;

// payload
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

// ct
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
#[allow(dead_code)]
const NFTA_CT_SREG: u16 = 4;
const NFT_CT_MARK: u32 = 3;
const NFT_CT_STATE: u32 = 0;

// immediate (for verdicts)
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NF_ACCEPT: i32 = 1;

// queue
const NFTA_QUEUE_NUM: u16 = 1;
const NFTA_QUEUE_FLAGS: u16 = 3;
const NFT_QUEUE_FLAG_BYPASS: u16 = 1;

// tproxy
const NFTA_TPROXY_FAMILY: u16 = 1;
const NFTA_TPROXY_REG_PORT: u16 = 3;

// data wrapper
const NFTA_DATA_VALUE: u16 = 1;

// bitwise
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;

// Registers
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG32_00: u32 = 8;
#[allow(dead_code)]
const NFT_REG32_01: u32 = 9;

// Hook numbers
const NF_INET_PRE_ROUTING: u32 = 0;

// Priority: mangle = -150
const NF_IP_PRI_MANGLE: i32 = -150;

// nfgenmsg
#[repr(C)]
struct Nfgenmsg {
    nfgen_family: u8,
    version: u8,
    res_id: u16,
}

// Conntrack state bits
const NF_CT_STATE_BIT_ESTABLISHED: u32 = 1 << 1; // IP_CT_ESTABLISHED

const TABLE_NAME: &str = "tls_guard";
const CHAIN_NAME: &str = "prerouting";

/// Print the equivalent nftables rules (for --print-nftables).
pub fn print_nft_rules(
    iface: &str,
    listen_port: u16,
    queue_num: u16,
    upgrader_port: u16,
    rules: &[PortRule],
) {
    println!("table ip {} {{", TABLE_NAME);
    println!("    chain {} {{", CHAIN_NAME);
    println!("        type filter hook prerouting priority mangle; policy accept;");

    // Upgrade rules (unconditional TPROXY)
    for (plain_port, _tls_port) in portmap::upgrade_rules(rules) {
        println!(
            "        iifname \"{}\" tcp dport {} meta mark set 0x2 tproxy to :{} accept",
            iface, plain_port, upgrader_port
        );
    }

    // Guard/proxy rules (NFQUEUE classification)
    for port in portmap::guard_proxy_ports(rules) {
        println!(
            "        iifname \"{}\" tcp dport {} ct mark 0x1 accept",
            iface, port
        );
        println!(
            "        iifname \"{}\" tcp dport {} ct mark 0x2 tproxy to :{} accept",
            iface, port, listen_port
        );
        println!(
            "        iifname \"{}\" tcp dport {} ct state established queue num {} bypass",
            iface, port, queue_num
        );
    }

    println!("    }}");
    println!("}}");
}

// ---------------------------------------------------------------------------
// Expression builders
// ---------------------------------------------------------------------------

fn put_expr_start(msg: &mut MnlMsg, name: &str) -> (mnl::NestToken, mnl::NestToken) {
    let elem = msg.nest_start(NFTA_LIST_ELEM);
    msg.put_strz(NFTA_EXPR_NAME, name);
    let data = msg.nest_start(NFTA_EXPR_DATA);
    (elem, data)
}

fn put_expr_end(msg: &mut MnlMsg, tokens: (mnl::NestToken, mnl::NestToken)) {
    msg.nest_end(tokens.1);
    msg.nest_end(tokens.0);
}

fn put_expr_meta(msg: &mut MnlMsg, key: u32, dreg: u32) {
    let t = put_expr_start(msg, "meta");
    msg.put_u32(NFTA_META_KEY, key.to_be());
    msg.put_u32(NFTA_META_DREG, dreg.to_be());
    put_expr_end(msg, t);
}

fn put_expr_meta_set(msg: &mut MnlMsg, key: u32, sreg: u32) {
    let t = put_expr_start(msg, "meta");
    msg.put_u32(NFTA_META_KEY, key.to_be());
    msg.put_u32(NFTA_META_SREG, sreg.to_be());
    put_expr_end(msg, t);
}

fn put_expr_cmp(msg: &mut MnlMsg, sreg: u32, op: u32, data: &[u8]) {
    let t = put_expr_start(msg, "cmp");
    msg.put_u32(NFTA_CMP_SREG, sreg.to_be());
    msg.put_u32(NFTA_CMP_OP, op.to_be());
    let data_nest = msg.nest_start(NFTA_CMP_DATA);
    msg.put(NFTA_DATA_VALUE, data);
    msg.nest_end(data_nest);
    put_expr_end(msg, t);
}

fn put_expr_payload(msg: &mut MnlMsg, dreg: u32, base: u32, offset: u32, len: u32) {
    let t = put_expr_start(msg, "payload");
    msg.put_u32(NFTA_PAYLOAD_DREG, dreg.to_be());
    msg.put_u32(NFTA_PAYLOAD_BASE, base.to_be());
    msg.put_u32(NFTA_PAYLOAD_OFFSET, offset.to_be());
    msg.put_u32(NFTA_PAYLOAD_LEN, len.to_be());
    put_expr_end(msg, t);
}

fn put_expr_ct_load(msg: &mut MnlMsg, key: u32, dreg: u32) {
    let t = put_expr_start(msg, "ct");
    msg.put_u32(NFTA_CT_KEY, key.to_be());
    msg.put_u32(NFTA_CT_DREG, dreg.to_be());
    put_expr_end(msg, t);
}

#[allow(dead_code)]
fn put_expr_ct_set(msg: &mut MnlMsg, key: u32, sreg: u32) {
    let t = put_expr_start(msg, "ct");
    msg.put_u32(NFTA_CT_KEY, key.to_be());
    msg.put_u32(NFTA_CT_SREG, sreg.to_be());
    put_expr_end(msg, t);
}

fn put_expr_immediate_data(msg: &mut MnlMsg, dreg: u32, data: &[u8]) {
    let t = put_expr_start(msg, "immediate");
    msg.put_u32(NFTA_IMMEDIATE_DREG, dreg.to_be());
    let data_nest = msg.nest_start(NFTA_IMMEDIATE_DATA);
    msg.put(NFTA_DATA_VALUE, data);
    msg.nest_end(data_nest);
    put_expr_end(msg, t);
}

fn put_expr_immediate_verdict(msg: &mut MnlMsg, verdict: i32) {
    let t = put_expr_start(msg, "immediate");
    msg.put_u32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT.to_be());
    let data_nest = msg.nest_start(NFTA_IMMEDIATE_DATA);
    let verd_nest = msg.nest_start(NFTA_DATA_VERDICT);
    msg.put_u32(NFTA_VERDICT_CODE, verdict as u32);
    msg.nest_end(verd_nest);
    msg.nest_end(data_nest);
    put_expr_end(msg, t);
}

fn put_expr_queue(msg: &mut MnlMsg, num: u16) {
    let t = put_expr_start(msg, "queue");
    msg.put_u16(NFTA_QUEUE_NUM, num.to_be());
    msg.put_u16(NFTA_QUEUE_FLAGS, NFT_QUEUE_FLAG_BYPASS.to_be());
    put_expr_end(msg, t);
}

fn put_expr_tproxy(msg: &mut MnlMsg, port_reg: u32) {
    let t = put_expr_start(msg, "tproxy");
    msg.put_u32(NFTA_TPROXY_FAMILY, (libc::AF_INET as u32).to_be());
    msg.put_u32(NFTA_TPROXY_REG_PORT, port_reg.to_be());
    put_expr_end(msg, t);
}

fn put_expr_bitwise(msg: &mut MnlMsg, sreg: u32, dreg: u32, len: u32, mask: &[u8], xor: &[u8]) {
    let t = put_expr_start(msg, "bitwise");
    msg.put_u32(NFTA_BITWISE_SREG, sreg.to_be());
    msg.put_u32(NFTA_BITWISE_DREG, dreg.to_be());
    msg.put_u32(NFTA_BITWISE_LEN, len.to_be());
    let mask_nest = msg.nest_start(NFTA_BITWISE_MASK);
    msg.put(NFTA_DATA_VALUE, mask);
    msg.nest_end(mask_nest);
    let xor_nest = msg.nest_start(NFTA_BITWISE_XOR);
    msg.put(NFTA_DATA_VALUE, xor);
    msg.nest_end(xor_nest);
    put_expr_end(msg, t);
}

// ---------------------------------------------------------------------------
// Common rule preamble: match iifname + tcp dport 443
// ---------------------------------------------------------------------------

fn put_match_iface_tcp_dport(msg: &mut MnlMsg, iface: &str, port: u16) {
    // meta load iifname => reg1
    put_expr_meta(msg, NFT_META_IIFNAME, NFT_REG32_00);
    // cmp eq iface
    let mut iface_bytes = [0u8; 16];
    let name = iface.as_bytes();
    let len = name.len().min(15);
    iface_bytes[..len].copy_from_slice(&name[..len]);
    put_expr_cmp(msg, NFT_REG32_00, NFT_CMP_EQ, &iface_bytes[..len + 1]);

    // meta load l4proto => reg1
    put_expr_meta(msg, NFT_META_L4PROTO, NFT_REG32_00);
    // cmp eq IPPROTO_TCP (6)
    put_expr_cmp(msg, NFT_REG32_00, NFT_CMP_EQ, &[libc::IPPROTO_TCP as u8]);

    // payload load transport header, offset 2, len 2 (dest port) => reg1
    put_expr_payload(msg, NFT_REG32_00, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2);
    // cmp eq port (network byte order)
    put_expr_cmp(msg, NFT_REG32_00, NFT_CMP_EQ, &port.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Message builders
// ---------------------------------------------------------------------------

fn build_batch_begin(seq: u32) -> MnlMsg {
    let mut msg = MnlMsg::new(
        batch_msg(NFNL_MSG_BATCH_BEGIN),
        flags::NLM_F_REQUEST,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0; // NFNETLINK_V0
    nfg.res_id = 0;
    msg
}

fn build_batch_end(seq: u32) -> MnlMsg {
    let mut msg = MnlMsg::new(
        batch_msg(NFNL_MSG_BATCH_END),
        flags::NLM_F_REQUEST,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg
}

fn build_new_table(seq: u32) -> MnlMsg {
    let mut msg = MnlMsg::new(
        nft_msg(NFT_MSG_NEWTABLE),
        flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg.put_strz(NFTA_TABLE_NAME, TABLE_NAME);
    msg
}

fn build_new_chain(seq: u32) -> MnlMsg {
    let mut msg = MnlMsg::new(
        nft_msg(NFT_MSG_NEWCHAIN),
        flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg.put_strz(NFTA_CHAIN_TABLE, TABLE_NAME);
    msg.put_strz(NFTA_CHAIN_NAME, CHAIN_NAME);
    msg.put_strz(NFTA_CHAIN_TYPE, "filter");

    // Hook: prerouting at mangle priority
    let hook = msg.nest_start(NFTA_CHAIN_HOOK);
    msg.put_u32(NFTA_HOOK_HOOKNUM, NF_INET_PRE_ROUTING.to_be());
    msg.put_u32(NFTA_HOOK_PRIORITY, (NF_IP_PRI_MANGLE as u32).to_be());
    msg.nest_end(hook);

    msg
}

/// Rule 1: iifname $iface tcp dport 443 ct mark 0x1 accept
fn build_rule_modern_accept(seq: u32, iface: &str, port: u16) -> MnlMsg {
    let mut msg = MnlMsg::new(
        nft_msg(NFT_MSG_NEWRULE),
        flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg.put_strz(NFTA_RULE_TABLE, TABLE_NAME);
    msg.put_strz(NFTA_RULE_CHAIN, CHAIN_NAME);

    let exprs = msg.nest_start(NFTA_RULE_EXPRESSIONS);

    put_match_iface_tcp_dport(&mut msg, iface, port);

    // ct load mark => reg1
    put_expr_ct_load(&mut msg, NFT_CT_MARK, NFT_REG32_00);
    // cmp eq 0x00000001
    put_expr_cmp(&mut msg, NFT_REG32_00, NFT_CMP_EQ, &1u32.to_be_bytes());

    // verdict: accept
    put_expr_immediate_verdict(&mut msg, NF_ACCEPT);

    msg.nest_end(exprs);
    msg
}

/// Rule 2: iifname $iface tcp dport 443 ct mark 0x2 tproxy to :$port accept
fn build_rule_legacy_tproxy(seq: u32, iface: &str, dport: u16, tproxy_port: u16) -> MnlMsg {
    let mut msg = MnlMsg::new(
        nft_msg(NFT_MSG_NEWRULE),
        flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg.put_strz(NFTA_RULE_TABLE, TABLE_NAME);
    msg.put_strz(NFTA_RULE_CHAIN, CHAIN_NAME);

    let exprs = msg.nest_start(NFTA_RULE_EXPRESSIONS);

    put_match_iface_tcp_dport(&mut msg, iface, dport);

    // ct load mark => reg1
    put_expr_ct_load(&mut msg, NFT_CT_MARK, NFT_REG32_00);
    // cmp eq 0x00000002
    put_expr_cmp(&mut msg, NFT_REG32_00, NFT_CMP_EQ, &2u32.to_be_bytes());

    // immediate: load tproxy port into reg1 (network byte order)
    put_expr_immediate_data(&mut msg, NFT_REG32_00, &tproxy_port.to_be_bytes());

    // tproxy to port in reg1
    put_expr_tproxy(&mut msg, NFT_REG32_00);

    // verdict: accept
    put_expr_immediate_verdict(&mut msg, NF_ACCEPT);

    msg.nest_end(exprs);
    msg
}

/// Rule 3: iifname $iface tcp dport 443 ct state established queue num $n bypass
fn build_rule_queue(seq: u32, iface: &str, port: u16, queue_num: u16) -> MnlMsg {
    let mut msg = MnlMsg::new(
        nft_msg(NFT_MSG_NEWRULE),
        flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg.put_strz(NFTA_RULE_TABLE, TABLE_NAME);
    msg.put_strz(NFTA_RULE_CHAIN, CHAIN_NAME);

    let exprs = msg.nest_start(NFTA_RULE_EXPRESSIONS);

    put_match_iface_tcp_dport(&mut msg, iface, port);

    // ct load state => reg1
    put_expr_ct_load(&mut msg, NFT_CT_STATE, NFT_REG32_00);
    // bitwise: reg1 = (reg1 & ESTABLISHED_BIT) ^ 0
    put_expr_bitwise(
        &mut msg,
        NFT_REG32_00,
        NFT_REG32_00,
        4,
        &NF_CT_STATE_BIT_ESTABLISHED.to_be_bytes(),
        &0u32.to_be_bytes(),
    );
    // cmp neq 0 — but nftables uses cmp eq with the bit set
    put_expr_cmp(
        &mut msg,
        NFT_REG32_00,
        NFT_CMP_EQ,
        &NF_CT_STATE_BIT_ESTABLISHED.to_be_bytes(),
    );

    // queue
    put_expr_queue(&mut msg, queue_num);

    msg.nest_end(exprs);
    msg
}

/// Upgrade rule: iifname $iface tcp dport $dport meta mark set 0x2 tproxy to :$tproxy_port accept
///
/// Unconditional TPROXY — no NFQUEUE classification needed.
fn build_rule_direct_tproxy(seq: u32, iface: &str, dport: u16, tproxy_port: u16) -> MnlMsg {
    let mut msg = MnlMsg::new(
        nft_msg(NFT_MSG_NEWRULE),
        flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg.put_strz(NFTA_RULE_TABLE, TABLE_NAME);
    msg.put_strz(NFTA_RULE_CHAIN, CHAIN_NAME);

    let exprs = msg.nest_start(NFTA_RULE_EXPRESSIONS);

    put_match_iface_tcp_dport(&mut msg, iface, dport);

    // immediate: load fwmark value 0x2 into reg1
    put_expr_immediate_data(&mut msg, NFT_REG32_00, &2u32.to_be_bytes());
    // meta mark set reg1
    put_expr_meta_set(&mut msg, NFT_META_MARK, NFT_REG32_00);

    // immediate: load tproxy port into reg1
    put_expr_immediate_data(&mut msg, NFT_REG32_00, &tproxy_port.to_be_bytes());
    // tproxy to port in reg1
    put_expr_tproxy(&mut msg, NFT_REG32_00);

    // verdict: accept
    put_expr_immediate_verdict(&mut msg, NF_ACCEPT);

    msg.nest_end(exprs);
    msg
}

fn build_del_table(seq: u32) -> MnlMsg {
    let mut msg = MnlMsg::new(
        nft_msg(NFT_MSG_DELTABLE),
        flags::NLM_F_REQUEST | flags::NLM_F_ACK,
        seq,
    );
    let nfg: &mut Nfgenmsg = msg.put_extra_header();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = 0;
    nfg.res_id = 0;
    msg.put_strz(NFTA_TABLE_NAME, TABLE_NAME);
    msg
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create the tls_guard nftables table, chain, and rules.
pub fn create_nft_rules(
    iface: &str,
    listen_port: u16,
    queue_num: u16,
    upgrader_port: u16,
    rules: &[PortRule],
) -> io::Result<()> {
    let sock = MnlSocket::open(libc::NETLINK_NETFILTER)?;
    sock.bind(0, 0)?;

    let mut seq = 0u32;

    let mut batch = MnlBatch::new();

    seq += 1;
    batch.push(&build_batch_begin(seq));

    seq += 1;
    batch.push(&build_new_table(seq));

    seq += 1;
    batch.push(&build_new_chain(seq));

    // Upgrade rules (unconditional TPROXY)
    for (plain_port, _tls_port) in portmap::upgrade_rules(rules) {
        seq += 1;
        batch.push(&build_rule_direct_tproxy(seq, iface, plain_port, upgrader_port));
    }

    // Guard/proxy rules (NFQUEUE classification)
    for port in portmap::guard_proxy_ports(rules) {
        seq += 1;
        batch.push(&build_rule_modern_accept(seq, iface, port));

        seq += 1;
        batch.push(&build_rule_legacy_tproxy(seq, iface, port, listen_port));

        seq += 1;
        batch.push(&build_rule_queue(seq, iface, port, queue_num));
    }

    seq += 1;
    batch.push(&build_batch_end(seq));

    sock.send_raw(batch.as_bytes())?;

    // Read back ACKs — in batch mode, kernel sends one NLMSG_ERROR per
    // NLM_F_ACK message plus a final batch-end marker.
    let portid = sock.portid();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match sock.recv_into(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => break,
            Err(e) => return Err(e),
        };
        // seq=0 accepts any sequence in batch mode
        let ret = mnl::cb_run(&buf[..n], 0, portid)?;
        if ret == 0 {
            break;
        }
    }

    log::info!("nftables: created table ip {}", TABLE_NAME);
    Ok(())
}

/// Delete the tls_guard nftables table (and all its chains/rules).
pub fn delete_nft_table() -> io::Result<()> {
    let sock = MnlSocket::open(libc::NETLINK_NETFILTER)?;
    sock.bind(0, 0)?;

    let mut seq = 0u32;
    let mut batch = MnlBatch::new();

    seq += 1;
    batch.push(&build_batch_begin(seq));

    seq += 1;
    batch.push(&build_del_table(seq));

    seq += 1;
    batch.push(&build_batch_end(seq));

    sock.send_raw(batch.as_bytes())?;

    // Best-effort ACK read
    let mut buf = vec![0u8; 8192];
    let _ = sock.recv_into(&mut buf);

    log::info!("nftables: deleted table ip {}", TABLE_NAME);
    Ok(())
}

