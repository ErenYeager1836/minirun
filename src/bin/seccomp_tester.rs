use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: seccomp_tester <test-case>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "ptrace" => {
            let res = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("res={},errno={}", res, errno);
        }
        "unshare" => {
            let res = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("res={},errno={}", res, errno);
        }
        "clone_newuser" => {
            // Syscall 56 is SYS_clone on x86_64
            let res = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong,
                    0usize,
                    0usize,
                    0usize,
                    0usize,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("res={},errno={}", res, errno);
        }
        "mount" => {
            let target = std::ffi::CString::new("/tmp").unwrap();
            let fstype = std::ffi::CString::new("tmpfs").unwrap();
            let source = std::ffi::CString::new("none").unwrap();
            let res = unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    fstype.as_ptr(),
                    0,
                    std::ptr::null(),
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("res={},errno={}", res, errno);
        }
        "fsopen" => {
            let fstype = std::ffi::CString::new("tmpfs").unwrap();
            let res = unsafe { libc::syscall(430 /* fsopen */, fstype.as_ptr(), 0) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("res={},errno={}", res, errno);
        }
        "bpf" => {
            let res = unsafe { libc::syscall(321 /* bpf */, 0, 0, 0) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("res={},errno={}", res, errno);
        }
        "x32_ptrace" => {
            // Syscall nr with x32 ABI bit (0x40000000 | 101)
            let res = unsafe { libc::syscall(0x40000000 | libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("res={},errno={}", res, errno);
        }
        "threading" => {
            let handle = std::thread::spawn(|| {
                println!("thread_alive");
            });
            handle.join().unwrap();
        }
        other => {
            eprintln!("Unknown test case: {}", other);
            std::process::exit(1);
        }
    }
}
