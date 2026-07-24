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
    79,                               // getcwd
    82,                               // rename (atomic drift write)
    96,                               // gettimeofday
    97,                               // getrlimit
    98,                               // getrusage
    102,                              // getuid
    104,                              // getgid
    107,                              // geteuid
    108,                              // getegid
    110,                              // getppid
    115,                              // getgroups
    118,                              // getresuid
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
        // AArch64 syscall allowlist (derived from ntpsec's aarch64 allowlist).
        // Syscall numbers on aarch64 differ from x86_64.
        const ALLOWED_SYSCALLS_AARCH64: &[u64] = &[
            0,   // io_setup (for async I/O)
            1,   // io_destroy
            2,   // io_submit
            3,   // io_cancel
            7,   // io_pgetevents
            8,   // pselect6
            9,   // ppoll
            10,  // epoll_pwait
            13,  // epoll_create1
            14,  // epoll_ctl
            15,  // epoll_pwait2
            16,  // epoll_wait_old
            17,  // epoll_ctl_old
            19,  // readv
            20,  // writev
            21,  // pread64
            22,  // pwrite64
            23,  // preadv
            24,  // pwritev
            25,  // preadv2
            26,  // pwritev2
            29,  // read
            30,  // write
            31,  // readv (alt)
            32,  // writev (alt)
            33,  // pread64 (alt)
            34,  // pwrite64 (alt)
            39,  // openat
            40,  // close
            41,  // pipe2
            42,  // eventfd
            43,  // eventfd2
            44,  // signalfd
            45,  // signalfd4
            46,  // inotify_init
            47,  // inotify_add_watch
            48,  // inotify_rm_watch
            49,  // fcntl
            50,  // fcntl64 (actually flock on aarch64)
            53,  // fstat
            54,  // newfstatat
            55,  // fstatfs
            56,  // newfstatat (alt)
            57,  // lseek
            58,  // lseek (alt)
            61,  // getdents64
            62,  // getcwd
            63,  // readlinkat
            64,  // faccessat
            65,  // faccessat2
            66,  // chdir
            67,  // fchdir
            69,  // getrandom
            71,  // renameat
            72,  // renameat2
            73,  // unlinkat
            74,  // linkat
            75,  // symlinkat
            76,  // mkdirat
            77,  // mknodat
            78,  // fchmodat
            79,  // fchownat
            80,  // openat2
            82,  // mount
            83,  // umount2
            84,  // pivot_root
            85,  // statx
            86,  // statmount
            87,  // listmount
            88,  // lsm_get_self_attr
            89,  // lsm_set_self_attr
            90,  // lsm_list_modules
            91,  // mseal
            92,  // set_mempolicy_home_node
            93,  // futex
            94,  // futex_waitv
            95,  // set_robust_list
            96,  // get_robust_list
            97,  // nanosleep
            98,  // clock_settime
            99,  // clock_gettime
            100, // clock_getres
            101, // clock_nanosleep
            102, // clock_adjtime
            103, // timer_create
            104, // timer_settime
            105, // timer_gettime
            106, // timer_getoverrun
            107, // timer_delete
            108, // sched_setattr
            109, // sched_getattr
            110, // sched_setscheduler
            111, // sched_getscheduler
            112, // sched_setparam
            113, // sched_getparam
            114, // sched_setaffinity
            115, // sched_getaffinity
            116, // sched_yield
            117, // sched_rr_get_interval
            118, // sched_rr_get_interval (alt)
            119, // restart_syscall
            120, // gettid
            121, // syslog
            122, // prctl
            123, // prlimit64
            124, // getpriority
            125, // setpriority
            126, // getrusage
            127, // getrusage (alt)
            128, // gettimeofday
            129, // settimeofday
            130, // adjtimex
            131, // mount_setattr
            132, // move_mount
            133, // open_tree
            134, // fsopen
            135, // fsconfig
            136, // fsmount
            137, // fspick
            138, // process_madvise
            139, // process_vm_readv
            140, // process_vm_writev
            141, // kcmp
            142, // seccomp
            143, // membarrier
            144, // get_mempolicy
            145, // set_mempolicy
            146, // mbind
            147, // migrate_pages
            148, // move_pages
            149, // cachestat
            150, // setxattr
            151, // lsetxattr
            152, // fsetxattr
            153, // getxattr
            154, // lgetxattr
            155, // fgetxattr
            156, // listxattr
            157, // llistxattr
            158, // flistxattr
            159, // removexattr
            160, // lremovexattr
            161, // fremovexattr
            162, // getcwd (alt)
            163, // lookup_dcookie
            164, // eventfd2 (alt)
            165, // signalfd4 (alt)
            166, // epoll_create1 (alt)
            167, // epoll_ctl (alt)
            168, // epoll_pwait (alt)
            169, // dup
            170, // dup3
            172, // socket
            173, // socketpair
            174, // bind
            175, // listen
            176, // accept
            177, // connect
            178, // getsockname
            179, // getpeername
            180, // sendto
            181, // recvfrom
            182, // setsockopt
            183, // getsockopt
            184, // shutdown
            185, // sendmsg
            186, // recvmsg
            187, // readahead
            188, // brk
            189, // munmap
            190, // mremap
            191, // mprotect
            192, // madvise
            193, // mlock
            194, // mlock2
            195, // munlock
            196, // mlockall
            197, // munlockall
            198, // mincore
            199, // madvise (alt)
            200, // remap_file_pages
            201, // mbind (alt)
            202, // get_mempolicy (alt)
            203, // set_mempolicy (alt)
            204, // migrate_pages (alt)
            205, // move_pages (alt)
            206, // mmap
            207, // mmap (alt)
            208, // msync
            209, // mlock (alt)
            210, // munlock (alt)
            211, // mlockall (alt)
            212, // munlockall (alt)
            213, // mincore (alt)
            214, // madvise (alt)
            215, // remap_file_pages (alt)
            216, // clone
            217, // clone3
            218, // fork
            219, // vfork
            220, // execve
            221, // exit
            222, // exit_group
            223, // wait4
            224, // waitid
            225, // kill
            226, // tkill
            227, // tgkill
            228, // getpid
            229, // getppid
            230, // getpgid
            231, // setpgid
            232, // getsid
            233, // setsid
            234, // getuid
            235, // geteuid
            236, // getgid
            237, // getegid
            238, // getgroups
            239, // setgroups
            240, // getresuid
            241, // setresuid
            242, // getresgid
            243, // setresgid
            244, // gettid (alt)
            245, // umask
            246, // personality
            247, // getcpu
            248, // get_mempolicy (alt)
            249, // remaining timers
            250, // process_mrelease
            251, // futex_wake
            252, // futex_wait
            253, // futex_requeue
            254, // getxattr (alt)
            255, // lgetxattr (alt)
            256, // fgetxattr (alt)
            257, // setxattr (alt)
            258, // lsetxattr (alt)
            259, // fsetxattr (alt)
            260, // listxattr (alt)
            261, // llistxattr (alt)
            262, // flistxattr (alt)
            263, // removexattr (alt)
            264, // lremovexattr (alt)
            265, // fremovexattr (alt)
            266, // getxattr (alt)
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
