// ──── ntp_sandbox.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_sandbox.c
//
// Seccomp-BPF sandboxing for Linux. Installs a seccomp filter that restricts
// system calls to a proven allowlist.
//
// ## Oracle
//   - ntpsec ntpd/ntp_sandbox.c (17K)
// =============================================================================

use libc;

/// Enable the seccomp sandbox.
///
/// 1. Sets PR_SET_NO_NEW_PRIVS.
/// 2. Installs seccomp BPF filter with x86_64-validated allowlist.
pub fn enable_sandbox() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(format!(
                "PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        install_seccomp_filter()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("seccomp is only supported on Linux".to_string())
    }
}

/// Check if NO_NEW_PRIVS is set.
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

/// Check if seccomp filter is installed.
pub fn is_seccomp_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        ret == 2 // SECCOMP_MODE_FILTER
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// ──── BPF constants ───────────────────────────────────────────────────────

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// ──── x86_64 syscall allowlist (derived from full lifecycle strace) ───────
// Covers: startup, polling, Mode 6, stats append, drift write+rename, shutdown.
// Removed: execve, setuid, setgid, mkdir, link, symlink, fanotify_*.
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
    23,  // pselect6/select
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
    54,  // setsockopt
    55,  // getsockopt
    56,  // clone (signal threads created before seccomp)
    60,  // exit
    61,  // wait4
    62,  // kill
    63,  // uname
    72,  // fcntl
    78,  // getdents64
    79,  // getcwd
    82,  // rename (atomic drift write)
    96,  // gettimeofday
    97,  // getrlimit
    98,  // getrusage
    102, // getuid
    104, // getgid
    107, // geteuid
    108, // getegid
    110, // getppid
    115, // getgroups
    118, // getresuid
    120, // getresgid
    123, // gettid
    131, // sigaltstack
    137, // statfs
    138, // fstatfs
    143, // getpriority
    157, // prctl
    158, // arch_prctl
    202, // futex
    217, // getdents64
    228, // clock_gettime
    229, // clock_getres
    231, // exit_group
    232, // epoll_wait
    233, // epoll_ctl
    234, // tgkill
    243, // set_tid_address
    247, // clock_adjtime
    257, // openat
    262, // newfstatat
    267, // faccessat
    273, // set_robust_list
    281, // pipe2
    290, // eventfd2
    293, // signalfd4
    302, // prlimit64
    307, // sendmmsg
    316, // renameat
    318, // getrandom
    332, // statx
    334, // rseq
    435, // clone3 (modern glibc thread creation)
];

/// Install seccomp BPF filter.
///
/// Filter structure:
///   LD arch
///   JEQ x86_64 → skip 1 (continue to syscall check)
///   RET KILL   (arch mismatch → die)
///   for each syscall nr in allowlist:
///     LD nr
///     JEQ syscall_nr → skip ALLOW (allow this syscall)
///     RET ALLOW
///   RET KILL  (no syscall matched → die)
#[cfg(target_os = "linux")]
fn install_seccomp_filter() -> Result<(), String> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        return Err("seccomp only supports x86_64".to_string());
    }

    #[cfg(target_arch = "x86_64")]
    {
        let mut filter: Vec<libc::sock_filter> = Vec::new();

        // ── Architecture check: kill if not x86_64 ─────────────────────
        filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
        filter.push(bpf_stmt(
            BPF_RET | BPF_K,
            libc::SECCOMP_RET_KILL_PROCESS as u32,
        ));

        // ── Syscall number check ───────────────────────────────────────
        // Load syscall number (once, before the jump chain)
        filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        // Jump chain: each syscall has JEQ nr, jt=0, jf=1 → RET ALLOW
        // If match (jt=0): fall through to ALLOW
        // If no match (jf=1): skip one (the ALLOW), continue to next JEQ
        for &nr in ALLOWED_SYSCALLS {
            filter.push(bpf_jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                nr as u32,
                0, // jt=0: if equal, fall through to ALLOW
                1, // jf=1: if not equal, skip the next ALLOW instruction
            ));
            filter.push(bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW as u32));
        }
        // No syscall matched — kill process
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

        // Use TSYNC to propagate filter to all existing threads (signal handlers)
        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC as i32,
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

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_active_by_default() {
        assert!(!is_sandbox_active());
        assert!(!is_seccomp_active());
    }

    #[test]
    fn test_enable_seccomp() {
        #[cfg(target_os = "linux")]
        {
            let result = enable_sandbox();
            assert!(result.is_ok(), "seccomp enable failed: {:?}", result.err());
            assert!(is_sandbox_active(), "NO_NEW_PRIVS must be set");
            assert!(
                is_seccomp_active(),
                "seccomp must be in FILTER mode after enable"
            );
            // Verify an allowed syscall works
            let allowed_pid = unsafe { libc::getpid() };
            assert!(allowed_pid > 0, "allowed syscall must succeed");
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(enable_sandbox().is_err());
        }
    }

    #[test]
    fn test_forbidden_syscall_with_child() {
        // Use a child process because SECCOMP_RET_KILL_PROCESS kills the caller.
        #[cfg(target_os = "linux")]
        {
            enable_sandbox().expect("seccomp must be installed for this test");
                    // Fork a child that attempts a forbidden syscall (mount = 165 on x86_64)
                    let pid = unsafe { libc::fork() };
                    if pid == 0 {
                        // Child: try mount (not in allowlist)
                        let src = std::ffi::CString::new("").unwrap();
                        let dst = std::ffi::CString::new("").unwrap();
                        let fs = std::ffi::CString::new("").unwrap();
                        unsafe {
                            libc::syscall(
                                libc::SYS_mount,
                                src.as_ptr(),
                                dst.as_ptr(),
                                fs.as_ptr(),
                                0u64,
                                std::ptr::null::<u8>(),
                            )
                        };
                        // If we reach here, seccomp didn't kill us — exit with failure
                        unsafe { libc::_exit(42) };
                    } else if pid > 0 {
                        // Parent: wait for child
                        let mut status: i32 = 0;
                        unsafe { libc::waitpid(pid, &mut status, 0) };
                        // Child should have been killed by SIGSYS (signal 31)
                        assert!(
                            libc::WIFSIGNALED(status),
                            "child should have been killed by signal"
                        );
                        assert_eq!(
                            libc::WTERMSIG(status),
                            31, // SIGSYS
                            "child should have died from SIGSYS (seccomp violation)"
                        );
                    } else {
                        panic!("fork failed");
                    }
            }
        }
    }
}
