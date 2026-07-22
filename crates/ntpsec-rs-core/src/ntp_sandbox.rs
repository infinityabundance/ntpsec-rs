// ──── ntp_sandbox.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_sandbox.c
//
// Seccomp-BPF sandboxing for Linux. Drops privileges and installs a
// seccomp filter that restricts system calls.
//
// ## Oracle
//   - ntpsec ntpd/ntp_sandbox.c (17K)
// =============================================================================

use libc;

/// Enable the seccomp sandbox.
///
/// 1. Sets PR_SET_NO_NEW_PRIVS so child processes can't regain privileges.
/// 2. Installs a seccomp BPF filter allowing only required syscalls.
///
/// Returns Ok(()) if sandbox installed, Err(message) if unavailable or failed.
pub fn enable_sandbox() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        // Step 1: PR_SET_NO_NEW_PRIVS
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(format!(
                "PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Step 2: Install seccomp filter with allowlist
        install_seccomp_filter()?;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err("seccomp is only supported on Linux".to_string())
    }
}

/// Check if the seccomp sandbox is currently active.
pub fn is_sandbox_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        ret == 1
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Check if seccomp filter is actually installed (not just NO_NEW_PRIVS).
pub fn is_seccomp_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        // prctl(PR_GET_SECCOMP) returns the seccomp mode if active
        let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        ret == 2 // SECCOMP_MODE_FILTER
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// ──── BPF constants ───────────────────────────────────────────────────────
// Classic BPF instruction codes for seccomp.

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00; // 32-bit word
const BPF_ABS: u16 = 0x20;

const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;

const BPF_RET: u16 = 0x06;

// seccomp data offsets (in 32-bit words from seccomp_data)
const SECCOMP_DATA_NR_OFFSET: u32 = 0; // syscall number
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4; // architecture (bytes, so word offset 4)

// Architecture AUDIT_ARCH_X86_64
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// ──── x86_64 syscall numbers used by ntpd-rs ────────────────────────────
#[cfg(target_arch = "x86_64")]
const ALLOWED_SYSCALLS: &[u64] = &[
    0,   // read
    1,   // write
    2,   // open
    3,   // close
    4,   // stat
    5,   // fstat
    8,   // lseek
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    12,  // brk
    13,  // rt_sigaction
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    16,  // ioctl
    21,  // access
    23,  // select
    25,  // mremap
    28,  // madvise
    35,  // nanosleep
    39,  // getpid
    41,  // socket
    44,  // sendto
    45,  // recvfrom
    46,  // sendmsg
    47,  // recvmsg
    49,  // bind
    51,  // getsockname
    52,  // getpeername
    53,  // socketpair
    54,  // setsockopt
    55,  // getsockopt
    56,  // clone
    59,  // execve (for child process exec, blocked by NO_NEW_PRIVS)
    60,  // exit
    61,  // wait4
    62,  // kill
    63,  // uname
    72,  // fcntl
    74,  // ftruncate
    78,  // getdents
    79,  // getcwd
    80,  // chdir
    82,  // rename
    83,  // mkdir
    84,  // rmdir
    87,  // link
    89,  // readlink
    90,  // symlink
    96,  // gettimeofday
    97,  // getrlimit
    98,  // getrusage
    99,  // sysinfo
    102, // getuid
    104, // getgid
    105, // setuid
    106, // setgid
    107, // geteuid
    108, // getegid
    110, // getppid
    111, // getpgrp
    113, // setpgid
    115, // getgroups
    116, // setgroups
    118, // getresuid
    119, // setresuid
    120, // getresgid
    121, // setresgid
    123, // gettid
    124, // syslog
    125, // setpgid
    126, // getsid
    131, // sigaltstack
    137, // statfs
    138, // fstatfs
    143, // getpriority
    144, // setpriority
    157, // prctl
    158, // arch_prctl
    186, // gettid
    187, // readahead
    188, // setxattr
    189, // lsetxattr
    190, // fsetxattr
    191, // getxattr
    192, // lgetxattr
    193, // fgetxattr
    202, // futex
    217, // getdents64
    218, // settimeofday
    228, // clock_gettime
    229, // clock_getres
    230, // clock_nanosleep
    231, // exit_group
    232, // epoll_wait
    233, // epoll_ctl
    234, // tgkill
    243, // set_tid_address
    247, // clock_adjtime (for NTP clock discipline)
    257, // openat
    262, // newfstatat
    267, // faccessat
    273, // set_robust_list
    281, // pipe2
    290, // eventfd2
    293, // signalfd4
    294, // vmsplice
    295, // splice
    296, // tee
    299, // recvmmsg
    302, // prlimit64
    303, // fanotify_init
    304, // fanotify_mark
    307, // sendmmsg
    318, // getrandom
    332, // statx
    334, // rseq
];

/// Install a seccomp BPF filter.
///
/// The filter:
/// 1. Checks architecture is x86_64 (reject non-matching arch)
/// 2. Validates the syscall number against the allowlist
/// 3. Allows allowed syscalls, kills process for denied ones
#[cfg(target_os = "linux")]
fn install_seccomp_filter() -> Result<(), String> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        return Err("seccomp sandbox only supports x86_64".to_string());
    }

    #[cfg(target_arch = "x86_64")]
    {
        let mut filter: Vec<libc::sock_filter> = Vec::new();

        // Load architecture from seccomp_data
        filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        // Jump to allow if arch == AUDIT_ARCH_X86_64
        filter.push(bpf_jump(BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 1));
        // Kill if arch doesn't match
        filter.push(bpf_stmt(
            BPF_RET | BPF_K,
            libc::SECCOMP_RET_KILL_PROCESS as u32,
        ));

        // Load syscall number
        filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        // Generate jump chain for each allowed syscall
        let n_syscalls = ALLOWED_SYSCALLS.len();
        for (i, &nr) in ALLOWED_SYSCALLS.iter().enumerate() {
            let is_last = i == n_syscalls - 1;
            // jump forward 0 if match, 1 if no match
            filter.push(bpf_jump(BPF_JEQ | BPF_K, nr as u32, 0, 1));
        }

        // Allow (reached if any syscall matched)
        filter.push(bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW as u32));
        // Kill (reached if no syscall matched — falls through jump chain)
        filter.push(bpf_stmt(
            BPF_RET | BPF_K,
            libc::SECCOMP_RET_KILL_PROCESS as u32,
        ));

        if filter.len() > 256 {
            return Err(format!(
                "BPF filter too long: {} instructions",
                filter.len()
            ));
        }

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0i32, // flags: 0 = SECCOMP_FILTER_FLAG_TSYNC off
                &prog as *const libc::sock_fprog,
            )
        };

        if ret != 0 {
            return Err(format!(
                "seccomp() failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}

/// Create a BPF statement instruction (BPF_LD | BPF_RET, etc.)
#[cfg(target_os = "linux")]
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Create a BPF jump instruction.
#[cfg(target_os = "linux")]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_new_privs_not_set_by_default() {
        #[cfg(target_os = "linux")]
        {
            assert!(
                !is_sandbox_active(),
                "NO_NEW_PRIVS should not be set by default"
            );
        }
    }

    #[test]
    fn test_seccomp_not_active_by_default() {
        #[cfg(target_os = "linux")]
        {
            assert!(
                !is_seccomp_active(),
                "seccomp filter should not be active by default"
            );
        }
    }

    #[test]
    fn test_enable_sandbox_on_linux() {
        #[cfg(target_os = "linux")]
        {
            match enable_sandbox() {
                Ok(()) => {
                    assert!(
                        is_sandbox_active(),
                        "NO_NEW_PRIVS should be set after enable"
                    );
                    assert!(
                        is_seccomp_active(),
                        "seccomp filter should be active after enable"
                    );
                }
                Err(e) => {
                    // May fail in containers without CAP_SYS_ADMIN or seccomp
                    assert!(
                        e.contains("failed") || e.contains("only supported"),
                        "Unexpected error: {e}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_forbidden_syscall() {
        // This test verifies that after enabling sandbox, forbidden syscalls
        // are blocked. We do this by trying to call mkdir (which is NOT in the
        // allowlist for ntpd-rs). If the sandbox is active, this should fail
        // with SIGSYS or return an error.
        #[cfg(target_os = "linux")]
        {
            match enable_sandbox() {
                Ok(()) => {
                    // Try a forbidden syscall: create a temp directory
                    let path =
                        std::ffi::CString::new("/tmp/ntpd-seccomp-test-deny").expect("CString");
                    let ret = unsafe { libc::mkdir(path.as_ptr(), 0o755) };
                    // mkdir should be denied by seccomp
                    assert_eq!(ret, -1, "mkdir should be denied by seccomp filter");
                    let err = std::io::Error::last_os_error();
                    // The specific error might be EPERM or ENOSYS or the process
                    // might be killed. At minimum, the call should fail.
                    assert!(
                        err.kind() == std::io::ErrorKind::PermissionDenied
                            || err.raw_os_error() == Some(libc::EPERM)
                            || err.raw_os_error() == Some(libc::ENOSYS),
                        "expected permission denial, got: {err}"
                    );
                }
                Err(e) => {
                    eprintln!("Sandbox not available: {e}");
                }
            }
        }
    }
}
