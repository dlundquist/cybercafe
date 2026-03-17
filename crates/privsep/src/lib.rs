//! Privilege separation helpers for daemon processes.
//!
//! Provides user lookup, uid/gid drop, and Linux capability wipe — the
//! three operations shared by ppp-server and tls-guard.

use std::ffi::CString;
use std::io;

/// Well-known Linux capability numbers (from linux/capability.h).
pub const CAP_NET_ADMIN: libc::c_ulong = 12;
pub const CAP_NET_RAW: libc::c_ulong = 13;

/// Resolve a username to (uid, gid) via `getpwnam(3)`.
pub fn lookup_user(name: &str) -> io::Result<(libc::uid_t, libc::gid_t)> {
    let c = CString::new(name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("user '{}' not found", name),
        ));
    }
    Ok(unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
}

/// Drop to the given uid/gid.
///
/// Clears supplementary groups, then calls `setgid` + `setuid` (in that
/// order — `setgid` requires uid 0).  Irreversible.
pub fn drop_privileges(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Drop all Linux capabilities from the current thread.
///
/// 1. Clears ambient capabilities (blocks inheritance to children).
/// 2. Drops each capability in `bounding_drop` from the bounding set
///    (prevents future regain via execve).
/// 3. Zeroes the effective + permitted + inheritable sets via `capset(2)`.
///
/// After this returns, the process cannot perform any privileged operation.
/// Call only after all privileged setup (socket bind, nftables, TUN, etc.)
/// is complete.
pub fn drop_capabilities(bounding_drop: &[libc::c_ulong]) -> io::Result<()> {
    // 1. Clear ambient capabilities
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        // EINVAL means ambient caps aren't supported (kernel < 4.3) — not fatal
        if e.raw_os_error() != Some(libc::EINVAL) {
            return Err(e);
        }
    }

    // 2. Drop named capabilities from the bounding set
    for &cap in bounding_drop {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // 3. Clear effective and permitted capability sets via capset(2)
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // _LINUX_CAPABILITY_VERSION_3 — two CapData structs (caps 0..31 and 32..63)
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0, // current thread
    };
    let data = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
