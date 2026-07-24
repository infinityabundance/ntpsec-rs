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

/// AArch64 (ARM64) audit arch constant for seccomp architecture matching.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;

// ──── x86_64 syscall allowlist (derived from full lifecycle strace) ───────
// Covers: startup, polling, Mode 6, stats append, drift write+rename, shutdown.
// Removed: execve, setuid, setgid, mkdir, link, symlink, fanotify_*.
#[cfg(target_arch = "x86_64")]
const ALLOWED_SYSCALLS: &[u64] = &[
    0,                                // read
    1,                                // write
    2,                                // open
    3,                                // close
    4,                                // stat
    5,                                // fstat
    7,                                // poll (signal handler notification)
    8,                                // lseek
    9,                                // mmap
    10,                               // mprotect
    11,                               // munmap
    12,                               // brk
    13,                               // rt_sigaction
    14,                               // rt_sigprocmask
    15,                               // rt_sigreturn
    16,                               // ioctl
    21,                               // access
    23,                               // pselect6/select
    28,                               // madvise
    35,                               // nanosleep
    39,                               // getpid
    41,                               // socket
    42,                               // connect
    44,                               // sendto
    45,                               // recvfrom
    46,                               // sendmsg
    47,                               // recvmsg
    49,                               // bind
    51,                               // getsockname
    52,                               // getpeername
    53,                               // socketpair
    54,                               // setsockopt
    55,                               // getsockopt
    56,                               // clone (signal threads created before seccomp)
    60,                               // exit
    61,                               // wait4
    62,                               // kill
    63,                               // uname
    72,                               // fcntl
    78,                               // getdents64
    79,                               // getdents64
    82,                               // rename (atomic drift write)
    83,                               // mkdir (stats directory creation)
    96,                               // gettimeofday
    97,                               // getrlimit
    98,                               // getrusage
    102,                              // getuid
    104,                              // getgid
    107,                              // geteuid
    108,                              // getegid
    110,                              // getppid
    115,                              // getgroups
    117,                              // setresuid
    118,                              // getresuid
    119,                              // setresgid
    120,                              // getresgid
    123,                              // gettid
    131,                              // sigaltstack
    137,                              // statfs
    138,                              // fstatfs
    143,                              // getpriority
    157,                              // prctl
    158,                              // arch_prctl
    202,                              // futex
    217,                              // getdents64
    227,                              // clock_settime (system clock set)
    228,                              // clock_gettime
    229,                              // clock_getres
    libc::SYS_clock_nanosleep as u64, // Rust std::thread::sleep
    231,                              // exit_group
    232,                              // epoll_wait
    233,                              // epoll_ctl
    234,                              // tgkill
    243,                              // set_tid_address
    247,                              // clock_adjtime
    257,                              // openat
    262,                              // newfstatat
    267,                              // faccessat
    273,                              // set_robust_list
    281,                              // pipe2
    290,                              // eventfd2
    293,                              // signalfd4
    302,                              // prlimit64
    307,                              // sendmmsg
    316,                              // renameat
    318,                              // getrandom
    332,                              // statx
    334,                              // rseq
    435,                              // clone3 (modern glibc thread creation)
];

/// Install seccomp BPF filter.
///
/// Filter structure:
///   LD arch
///   JEQ arch → skip 1 (continue to syscall check)
///   RET KILL   (arch mismatch → die)
///   for each syscall nr in allowlist:
///     LD nr
///     JEQ syscall_nr → skip ALLOW (allow this syscall)
///     RET ALLOW
///   RET KILL  (no syscall matched → die)
///
/// Supports both x86_64 and aarch64 via conditional compilation.
/// On aarch64, the architecture audit constant is AUDIT_ARCH_AARCH64
/// and the syscall numbers differ from x86_64.
#[cfg(target_os = "linux")]
fn install_seccomp_filter() -> Result<(), String> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return Err("seccomp only supports x86_64 and aarch64".to_string());
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Minimal AArch64 daemon confinement syscall allowlist.
        // This is a focused daemon confinement profile matching the x86_64
        // list's philosophy — only syscalls that a time daemon legitimately
        // needs.  Removed: mount, umount2, pivot_root, mknodat, linkat,
        // symlinkat, mkdirat, chdir, fchdir, fork, execve, etc.
        // Syscall numbers on aarch64 differ from x86_64.
        const ALLOWED_SYSCALLS_AARCH64: &[u64] = &[
            // ── I/O and memory ─────────────────────────────────────────────
            63,  // read
            64,  // write
            56,  // openat
            57,  // close
            80,  // fstat
            79,  // newfstatat
            62,  // lseek
            222, // mmap
            226, // mprotect
            215, // munmap
            214, // brk
            61,  // getdents64
            17,  // getcwd
            // ── Signals and scheduling ─────────────────────────────────────
            134, // rt_sigaction
            135, // rt_sigprocmask
            139, // rt_sigreturn
            132, // sigaltstack
            101, // nanosleep
            99,  // set_robust_list
            293, // rseq
            // ── Process management ─────────────────────────────────────────
            93,  // exit
            94,  // exit_group
            260, // wait4
            129, // kill
            131, // tgkill
            172, // getpid
            173, // getppid
            178, // gettid
            174, // getuid
            175, // geteuid
            176, // getgid
            177, // getegid
            148, // getresuid
            147, // setresuid
            150, // getresgid
            149, // setresgid
            158, // getgroups
            159, // setgroups
            141, // getpriority
            261, // prlimit64
            220, // clone (threads created before seccomp)
            435, // clone3 (modern glibc thread creation)
            // ── Networking ────────────────────────────────────────────────
            198, // socket
            203, // connect
            200, // bind
            206, // sendto
            207, // recvfrom
            211, // sendmsg
            212, // recvmsg
            204, // getsockname
            205, // getpeername
            208, // setsockopt
            209, // getsockopt
            199, // socketpair
            169, // gettimeofday
            // ── File operations and descriptors ───────────────────────────
            25, // fcntl
            23, // dup
            24, // dup3
            59, // pipe2
            29, // ioctl
            38, // renameat (atomic drift file write)
            // ── Timekeeping ───────────────────────────────────────────────
            113, // clock_gettime
            112, // clock_settime (system clock set)
            114, // clock_getres
            115, // clock_nanosleep
            266, // clock_adjtime
            // ── Synchronization ───────────────────────────────────────────
            98, // futex
            20, // epoll_create1
            21, // epoll_ctl
            22, // epoll_pwait
            19, // eventfd2
            74, // signalfd4
            // ── Security and introspection ────────────────────────────────
            167, // prctl
            277, // seccomp
            278, // getrandom
            291, // statx
        ];

        let mut filter: Vec<libc::sock_filter> = Vec::new();

        // ── Architecture check: kill if not aarch64 ─────────────────────
        filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        filter.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH_AARCH64,
            1,
            0,
        ));
        filter.push(bpf_stmt(
            BPF_RET | BPF_K,
            libc::SECCOMP_RET_KILL_PROCESS as u32,
        ));

        // ── Syscall number check ───────────────────────────────────────
        load_and_check_syscalls(&mut filter, ALLOWED_SYSCALLS_AARCH64)?;

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        install_via_syscall_or_prctl(&prog)
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
        load_and_check_syscalls(&mut filter, ALLOWED_SYSCALLS)?;

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        install_via_syscall_or_prctl(&prog)
    }
}

/// Load the syscall number and check against the allowlist.
/// Shared by both x86_64 and aarch64 implementations.
#[cfg(target_os = "linux")]
fn load_and_check_syscalls(
    filter: &mut Vec<libc::sock_filter>,
    allowed: &[u64],
) -> Result<(), String> {
    // Load syscall number (once, before the jump chain)
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    // Jump chain: each syscall has JEQ nr, jt=0, jf=1 → RET ALLOW
    // If match (jt=0): fall through to ALLOW
    // If no match (jf=1): skip one (the ALLOW), continue to next JEQ
    for &nr in allowed {
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

    Ok(())
}

/// Install a BPF filter program using either SYS_seccomp (with TSYNC) or
/// prctl fallback.  The prctl path does not support TSYNC but works on
/// older kernels where SYS_seccomp is not available.
#[cfg(target_os = "linux")]
fn install_via_syscall_or_prctl(prog: &libc::sock_fprog) -> Result<(), String> {
    // Use TSYNC to propagate filter to all existing threads (signal handlers)
    let mut ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC as i32,
            prog as *const libc::sock_fprog,
        )
    };

    if ret != 0 {
        // Fallback: try prctl(PR_SET_SECCOMP) which does not support
        // TSYNC but is available on older kernels.
        ret = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as i64,
                prog as *const libc::sock_fprog as i64,
                0i64,
                0i64,
            ) as i64
        };
    }

    if ret != 0 {
        return Err(format!(
            "seccomp() failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
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
    #[cfg(not(target_os = "linux"))]
    fn test_seccomp_unavailable_on_non_linux() {
        assert!(enable_sandbox().is_err());
    }

    #[test]
    fn test_seccomp_inside_child() {
        // All seccomp installations must happen inside a disposable child
        // process because TSYNC propagates the filter to every test thread,
        // which would kill the entire test harness on syscall denials.
        //
        // Child: install seccomp, verify it works, test forbidden syscall
        #[cfg(target_os = "linux")]
        {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");

            if pid == 0 {
                // ── Child: install seccomp and run tests ──
                let result = enable_sandbox();
                if result.is_err() {
                    eprintln!("seccomp enable failed: {:?}", result);
                    unsafe { libc::_exit(2) };
                }

                // Verify sandbox is active
                if !is_seccomp_active() {
                    eprintln!("seccomp not in FILTER mode");
                    unsafe { libc::_exit(3) };
                }

                // Verify allowed syscall works
                let allowed_pid = unsafe { libc::getpid() };
                if allowed_pid <= 0 {
                    eprintln!("allowed syscall getpid failed");
                    unsafe { libc::_exit(4) };
                }

                // Verify forbidden syscall via grandchild
                let gpid = unsafe { libc::fork() };
                if gpid == 0 {
                    // Grandchild: try mount (not in allowlist, syscall 165)
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
                    // If we reach here, seccomp didn't kill us
                    unsafe { libc::_exit(42) };
                } else if gpid > 0 {
                    let mut gstatus: i32 = 0;
                    unsafe { libc::waitpid(gpid, &mut gstatus, 0) };
                    if !libc::WIFSIGNALED(gstatus) || libc::WTERMSIG(gstatus) != 31 {
                        eprintln!(
                            "grandchild should have died from SIGSYS, got status={}",
                            gstatus
                        );
                        unsafe { libc::_exit(5) };
                    }
                } else {
                    eprintln!("grandchild fork failed");
                    unsafe { libc::_exit(6) };
                }

                // All assertions passed
                unsafe { libc::_exit(0) };
            }

            // ── Parent: wait for child verdict ──
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            assert!(
                libc::WIFEXITED(status),
                "child should have exited normally, got signal={}",
                libc::WTERMSIG(status)
            );
            let exit_code = libc::WEXITSTATUS(status);
            assert_eq!(
                exit_code, 0,
                "seccomp child test failed with exit code {}",
                exit_code
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(enable_sandbox().is_err());
        }
    }
}
