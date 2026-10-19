//! 两阶段 Linux runner，负责固定入口执行、输入输出预算和进程监督。
//!
//! supervise 等待单次 gate，再启动独立 exec 子进程；exec 路径在 fexecve 前保持单线程，
//! 重新核对入口和 cwd 身份、封存脚本内容，并仅传入显式环境与允许的文件描述符。
//! sandbox/prepare-scratch/collect/cleanup-scratch 是固定镜像中的受控辅助入口。
//! runner 的退出码描述主命令；整组进程是否停止仍由 systemd/gVisor 后端核实。

use orc_execution::*;
use std::path::PathBuf;

fn main() {
    if let Err(error) = dispatch() {
        eprintln!("{error}");
        std::process::exit(125);
    }
}
fn dispatch() -> Result<(), BackendError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 || args[1] != "--directory" {
        return Err(BackendError::Invalid(
            "usage: orc-runner supervise|exec --directory <private task directory>".into(),
        ));
    }
    let directory = PathBuf::from(&args[2]);
    if !directory.is_absolute() {
        return Err(BackendError::Invalid("absolute directory required".into()));
    }
    #[cfg(target_os = "linux")]
    {
        if args[0] == "cleanup-scratch" {
            return linux::cleanup_scratch(directory);
        }
        if args[0] == "prepare-scratch" {
            return linux::prepare_scratch(directory);
        }
        if args[0] == "collect" {
            return linux::collect(directory);
        }
        if args[0] == "sandbox" {
            return tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(linux::sandbox(directory));
        }
        linux::check_private_dir(&directory)?;
        match args[0].to_str() {
            Some("exec") => linux::exec_stage(&directory),
            Some("supervise") => tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(linux::supervise(directory))
                .map(|_| ()),
            _ => Err(BackendError::Invalid("unknown runner mode".into())),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        Err(BackendError::Unavailable("runner requires Linux".into()))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
        path::Path,
        process::Stdio,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub fn check_private_dir(directory: &Path) -> Result<(), BackendError> {
        let m = fs::symlink_metadata(directory)?;
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != uid
            || m.mode() & 0o077 != 0
            || uid == 0
        {
            return Err(BackendError::Invalid(
                "runner directory must be private and owned by the non-root execution UID".into(),
            ));
        }
        Ok(())
    }
    fn cstring(value: &[u8]) -> Result<std::ffi::CString, BackendError> {
        std::ffi::CString::new(value)
            .map_err(|_| BackendError::Invalid("NUL in execution value".into()))
    }
    fn boottime_ms() -> Result<u64, BackendError> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: time points to initialized writable timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((time.tv_sec as u64).saturating_mul(1000) + (time.tv_nsec as u64) / 1_000_000)
    }
    /// 单线程执行边界：复核 ELF/cwd、封存脚本、关闭继承 FD 后用 fexecve 替换进程。
    pub fn exec_stage(directory: &Path) -> Result<(), BackendError> {
        let resolved: ResolvedSpec = read_json(&directory.join("spec.json"), MAX_SPEC)?;
        resolved.validate_digest()?;
        resolved.spec.validate(unix_ms())?;
        // SAFETY: getuid and setpgid(0,0) operate on this process.
        if unsafe { libc::getuid() } != resolved.spec.execution_uid
            || unsafe { libc::setpgid(0, 0) } != 0
        {
            return Err(BackendError::Invalid(
                "execution UID or process group mismatch".into(),
            ));
        }
        let mut executable = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&resolved.entry.path)?;
        if inspect_entry_file(&mut executable, resolved.entry.path.clone())? != resolved.entry {
            return Err(BackendError::EntryChanged(
                "executable identity changed after approval".into(),
            ));
        }
        let cwd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&resolved.spec.cwd)?;
        let cwd_metadata = cwd.metadata()?;
        if cwd_metadata.dev() != resolved.cwd_device || cwd_metadata.ino() != resolved.cwd_inode {
            return Err(BackendError::EntryChanged(
                "working directory identity changed".into(),
            ));
        }
        // SAFETY: cwd is a valid open directory FD.
        if unsafe { libc::fchdir(cwd.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut argv = vec![cstring(resolved.entry.path.as_os_str().as_bytes())?];
        let mut script_fd: Option<OwnedFd> = None;
        match &resolved.spec.command {
            ExecutionCommand::Argv { args, .. } => {
                for arg in args {
                    argv.push(cstring(arg.as_bytes())?);
                }
            }
            ExecutionCommand::Script {
                source,
                source_path,
                interpreter_args,
                args,
                ..
            } => {
                if let Some(path) = source_path {
                    let mut file = fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(path)?;
                    let before = file.metadata()?;
                    let mut bytes = Vec::new();
                    (&mut file)
                        .take(MAX_SCRIPT as u64 + 1)
                        .read_to_end(&mut bytes)?;
                    let after = file.metadata()?;
                    if !before.is_file()
                        || before.len() != after.len()
                        || before.modified()? != after.modified()?
                        || bytes != source.as_bytes()
                    {
                        return Err(BackendError::EntryChanged(
                            "script file differs from approved bytes".into(),
                        ));
                    }
                }
                // 把批准字节复制到 sealed memfd；解释器通过继承 FD 读取，避免再次按原路径打开脚本。
                let name = cstring(b"orc-approved-script")?;
                // SAFETY: name is NUL terminated; successful memfd is owned exactly once.
                let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
                if raw < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                // SAFETY: raw 已检查成功，尚无其他拥有者；File 接管其关闭责任。
                let mut file = unsafe { fs::File::from_raw_fd(raw) };
                file.write_all(source.as_bytes())?;
                // SAFETY: fcntl/lseek operate on our live memfd; sealing disallows mutation.
                if unsafe {
                    libc::fcntl(
                        raw,
                        libc::F_ADD_SEALS,
                        libc::F_SEAL_WRITE
                            | libc::F_SEAL_GROW
                            | libc::F_SEAL_SHRINK
                            | libc::F_SEAL_SEAL,
                    )
                } < 0
                    || unsafe { libc::lseek(raw, 0, libc::SEEK_SET) } < 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                for arg in interpreter_args {
                    argv.push(cstring(arg.as_bytes())?);
                }
                argv.push(cstring(format!("/proc/self/fd/{raw}").as_bytes())?);
                for arg in args {
                    argv.push(cstring(arg.as_bytes())?);
                }
                script_fd = Some(file.into());
            }
        }
        let environment: Vec<_> = resolved
            .spec
            .env
            .iter()
            .map(|(k, v)| cstring(format!("{k}={v}").as_bytes()))
            .collect::<Result<_, _>>()?;
        let mut argv_ptrs: Vec<_> = argv.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut env_ptrs: Vec<_> = environment.iter().map(|s| s.as_ptr()).collect();
        env_ptrs.push(std::ptr::null());
        let executable_fd = executable.as_raw_fd();
        let script_raw = script_fd.as_ref().map(AsRawFd::as_raw_fd);
        // Close every inherited descriptor except standard IO, executable and approved script.
        // /proc listing is evaluated before closure and is bounded by this process's FD table.
        let descriptors: Vec<i32> = fs::read_dir("/proc/self/fd")?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
            .collect();
        for fd in descriptors {
            if fd > 2 && fd != executable_fd && Some(fd) != script_raw && fd != cwd.as_raw_fd() {
                // SAFETY: this single-threaded child owns no concurrent FD users.
                unsafe { libc::close(fd) };
            }
        }
        // SAFETY: executable FD is verified ELF, pointers live until this process is replaced.
        unsafe { libc::fexecve(executable_fd, argv_ptrs.as_ptr(), env_ptrs.as_ptr()) };
        Err(std::io::Error::last_os_error().into())
    }
    /// stdout/stderr 共用原子保留预算；超过预算仍持续排空管道，以免子进程被写满阻塞。
    async fn drain<R: tokio::io::AsyncRead + Unpin>(
        mut reader: R,
        path: PathBuf,
        remaining: Arc<AtomicU64>,
        truncated: Arc<AtomicBool>,
        total: Arc<AtomicU64>,
        framed_stream: Option<&'static str>,
        completed_bytes: Arc<AtomicU64>,
    ) -> Result<u64, BackendError> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let mut file = tokio::fs::File::from_std(file);
        let mut retained = 0;
        let mut buf = [0; 16 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total.fetch_add(n as u64, Ordering::Relaxed);
            let available = remaining
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_sub(n as u64))
                })
                .unwrap_or(0);
            let keep = available.min(n as u64) as usize;
            if keep < n {
                truncated.store(true, Ordering::Relaxed);
            }
            if keep > 0 {
                file.write_all(&buf[..keep]).await?;
                if let Some(stream) = framed_stream {
                    // One lock spans the complete bounded frame. A forced stop
                    // may lose the last frame, but preserves earlier output.
                    let mut output = std::io::stdout().lock();
                    serde_json::to_writer(
                        &mut output,
                        &OutputFrame::Chunk {
                            stream: stream.into(),
                            bytes: buf[..keep].to_vec(),
                        },
                    )?;
                    output.write_all(b"\n")?;
                    output.flush()?;
                }
                retained += keep as u64;
                completed_bytes.store(retained, Ordering::Release);
            }
        }
        file.sync_all().await?;
        Ok(retained)
    }
    async fn terminate(child: &mut tokio::process::Child) {
        if let Some(pid) = child.id() {
            // SAFETY: negative child PID targets its own process group only.
            unsafe { libc::kill(-(pid as i32), libc::SIGTERM) };
        }
        if tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .is_err()
        {
            if let Some(pid) = child.id() {
                // SAFETY: child 尚未回收，负 PID 仍只指向其建立的进程组。
                unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
    fn text_files(
        root: &Path,
        max_total: u64,
        max_files: usize,
    ) -> Result<Vec<PathBuf>, BackendError> {
        let mut pending = vec![root.to_owned()];
        let mut files = Vec::new();
        let mut total = 0u64;
        let mut entries = 0;
        while let Some(dir) = pending.pop() {
            for item in fs::read_dir(dir)? {
                let item = item?;
                entries += 1;
                if entries > 4000 {
                    return Err(BackendError::Invalid(
                        "artifact directory entry budget exceeded".into(),
                    ));
                }
                let ty = item.file_type()?;
                let path = item.path();
                if ty.is_symlink() || (!ty.is_dir() && !ty.is_file()) {
                    return Err(BackendError::Invalid(
                        "links and special files are not supported".into(),
                    ));
                }
                if ty.is_dir() {
                    pending.push(path);
                    continue;
                }
                let meta = item.metadata()?;
                total += meta.len();
                if meta.len() > 8 * 1024 * 1024 || total > max_total || files.len() >= max_files {
                    return Err(BackendError::Invalid("artifact budget exceeded".into()));
                }
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| BackendError::Invalid("invalid relative artifact path".into()))?;
                let name = rel
                    .to_str()
                    .ok_or_else(|| BackendError::Invalid("artifact names must be UTF-8".into()))?;
                if name.chars().any(|c| c.is_control()) || name.contains('\\') {
                    return Err(BackendError::Invalid("ambiguous artifact path".into()));
                }
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }
    pub fn cleanup_scratch(directory: PathBuf) -> Result<(), BackendError> {
        if directory.parent() != Some(Path::new("/pool")) {
            return Err(BackendError::Invalid("invalid scratch task path".into()));
        }
        let task_id = directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| BackendError::Invalid("invalid scratch task ID".into()))?;
        remove_stopped_task_scratch(Path::new("/pool"), task_id)
    }
    pub fn prepare_scratch(directory: PathBuf) -> Result<(), BackendError> {
        if directory.parent() != Some(Path::new("/pool"))
            || directory.file_name().is_none_or(|n| {
                !n.as_encoded_bytes()
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            })
        {
            return Err(BackendError::Invalid("invalid scratch task path".into()));
        }
        fs::create_dir(&directory)?;
        private_dir(&directory)?;
        for source in text_files(Path::new("/input"), 128 * 1024 * 1024, 2000)? {
            let target = directory.join(
                source
                    .strip_prefix("/input")
                    .map_err(|_| BackendError::Invalid("invalid input path".into()))?,
            );
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut input = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(source)?;
            let mut bytes = Vec::new();
            (&mut input)
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 8 * 1024 * 1024
                || bytes.contains(&0)
                || std::str::from_utf8(&bytes).is_err()
            {
                return Err(BackendError::Invalid(
                    "only bounded UTF-8 input text is supported".into(),
                ));
            }
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(target)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
        }
        Ok(())
    }
    pub fn collect(directory: PathBuf) -> Result<(), BackendError> {
        if directory != Path::new("/work") {
            return Err(BackendError::Invalid("collector root must be /work".into()));
        }
        let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
        for source in text_files(&directory, 64 * 1024 * 1024, 1000)? {
            let name = source
                .strip_prefix(&directory)
                .map_err(|_| BackendError::Invalid("invalid artifact path".into()))?
                .to_string_lossy()
                .into_owned();
            let mut file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&source)?;
            let before = file.metadata()?;
            let mut bytes = Vec::new();
            (&mut file)
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 8 * 1024 * 1024
                || bytes.contains(&0)
                || std::str::from_utf8(&bytes).is_err()
                || before.len() != file.metadata()?.len()
                || before.modified()? != file.metadata()?.modified()?
            {
                return Err(BackendError::Invalid(
                    "artifact is not stable bounded UTF-8 text".into(),
                ));
            }
            serde_json::to_writer(
                &mut stdout,
                &ArtifactFrame::File {
                    path: name,
                    bytes: bytes.len() as u64,
                    sha256: sha256(&bytes),
                },
            )?;
            stdout.write_all(b"\n")?;
            for chunk in bytes.chunks(16 * 1024) {
                serde_json::to_writer(
                    &mut stdout,
                    &ArtifactFrame::Chunk {
                        bytes: chunk.to_vec(),
                    },
                )?;
                stdout.write_all(b"\n")?;
            }
            serde_json::to_writer(&mut stdout, &ArtifactFrame::End)?;
            stdout.write_all(b"\n")?;
        }
        serde_json::to_writer(&mut stdout, &ArtifactFrame::Done)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        Ok(())
    }
    pub async fn sandbox(directory: PathBuf) -> Result<(), BackendError> {
        let request: SandboxRequest = read_json(&directory.join("request.json"), MAX_SPEC)?;
        if request.guest_process_limit == 0 || request.guest_process_limit > 128 {
            return Err(BackendError::Invalid("invalid guest process budget".into()));
        }
        let mut spec = request.spec;
        // The host execution UID identifies the owner. Container UID is fixed by
        // the rootless profile and independently checked here.
        // SAFETY: getuid 无指针或内存前置条件，读取当前容器进程的 UID。
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return Err(BackendError::Invalid(
                "sandbox workload must be non-root".into(),
            ));
        }
        spec.execution_uid = uid;
        let limit = libc::rlimit {
            rlim_cur: request.guest_process_limit,
            rlim_max: request.guest_process_limit,
        };
        // SAFETY: limit 是完整初始化的 rlimit，调用期间引用保持有效。
        if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let resolved = resolve_spec(spec)?;
        if resolved.entry.sha256 != request.expected_entry_sha256
            || resolved.entry.path != request.expected_entry_path
        {
            return Err(BackendError::EntryChanged(
                "image program does not match the approved environment manifest".into(),
            ));
        }
        let state = PathBuf::from("/tmp/orc-runner-state");
        fs::create_dir(&state)?;
        private_dir(&state)?;
        write_new_json(&state.join("spec.json"), &resolved)?;
        write_new_json(&state.join("gate.json"), &resolved.digest)?;
        let result = supervise_inner(state, true).await?;
        let mut output = std::io::BufWriter::new(std::io::stdout().lock());
        serde_json::to_writer(
            &mut output,
            &OutputFrame::Complete {
                result: result.clone(),
            },
        )?;
        output.write_all(b"\n")?;
        output.flush()?;
        std::process::exit(
            result
                .exit_code
                .unwrap_or(if result.reason == "deadline" {
                    124
                } else {
                    125
                })
                .clamp(0, 255),
        );
    }
    pub async fn supervise(directory: PathBuf) -> Result<RunnerResult, BackendError> {
        supervise_inner(directory, false).await
    }
    /// 消费单次 gate，监督 exec 子进程和输出；墙钟与包含休眠时间的时钟共同约束期限。
    async fn supervise_inner(
        directory: PathBuf,
        framed: bool,
    ) -> Result<RunnerResult, BackendError> {
        let resolved: ResolvedSpec = read_json(&directory.join("spec.json"), MAX_SPEC)?;
        resolved.validate_digest()?;
        resolved.spec.validate(unix_ms())?;
        let gate_start = boottime_ms()?;
        loop {
            if unix_ms() >= resolved.spec.deadline_unix_ms
                || boottime_ms()?.saturating_sub(gate_start) > 15_000
            {
                return Err(BackendError::Deadline);
            }
            match read_json::<String>(&directory.join("gate.json"), 1024) {
                Ok(digest) => {
                    if digest != resolved.digest {
                        return Err(BackendError::Invalid("launch gate digest mismatch".into()));
                    }
                    break;
                }
                Err(BackendError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(e) => return Err(e),
            }
        }
        // 先持久写 started 再移除 gate；崩溃可能留下未执行的尝试，但绝不能重复执行。
        write_new_json(&directory.join("started.json"), &resolved.digest).map_err(|e| match e {
            BackendError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists => {
                BackendError::AlreadyAttempted
            }
            other => other,
        })?;
        fs::remove_file(directory.join("gate.json"))?;
        fs::File::open(&directory)?.sync_all()?;
        let mut command = tokio::process::Command::new(std::env::current_exe()?);
        command
            .arg("exec")
            .arg("--directory")
            .arg(&directory)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| BackendError::Unknown("missing child stdin".into()))?;
        let input = resolved.spec.stdin.clone();
        let input_task = tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        });
        let remaining = Arc::new(AtomicU64::new(resolved.spec.output_limit_bytes));
        let truncated = Arc::new(AtomicBool::new(false));
        let total = Arc::new(AtomicU64::new(0));
        let stdout_completed = Arc::new(AtomicU64::new(0));
        let stderr_completed = Arc::new(AtomicU64::new(0));
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BackendError::Unknown("missing stdout".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BackendError::Unknown("missing stderr".into()))?;
        let mut out = tokio::spawn(drain(
            stdout,
            directory.join("stdout"),
            remaining.clone(),
            truncated.clone(),
            total.clone(),
            framed.then_some("stdout"),
            stdout_completed.clone(),
        ));
        let mut err = tokio::spawn(drain(
            stderr,
            directory.join("stderr"),
            remaining,
            truncated.clone(),
            total.clone(),
            framed.then_some("stderr"),
            stderr_completed.clone(),
        ));
        let start = boottime_ms()?;
        let budget = resolved.spec.deadline_unix_ms.saturating_sub(unix_ms());
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        let mut flood_start = None;
        let mut last_total = 0;
        let mut last_tick = boottime_ms()?;
        let (exit_code, reason) = loop {
            tokio::select! {
                status = child.wait() => {
                    let status = status?;
                    break (status.code(), if status.success() { "exit_zero" } else { "exit_nonzero" });
                },
                _ = interval.tick() => {
                    let now = boottime_ms()?;
                    let bytes = total.load(Ordering::Relaxed);
                    let elapsed = now.saturating_sub(last_tick);
                    // 保留预算限制磁盘占用；持续洪泛另按实际读入速率计时，
                    // 防止已截断输出仍无限消耗 CPU 和管道带宽。
                    if elapsed > 0
                        && bytes.saturating_sub(last_total).saturating_mul(1000) / elapsed > 4 * 1024 * 1024
                    {
                        if flood_start.is_none() {
                            flood_start = Some(now);
                        }
                    } else {
                        flood_start = None;
                    }
                    last_total = bytes;
                    last_tick = now;
                    if unix_ms() >= resolved.spec.deadline_unix_ms || now.saturating_sub(start) >= budget {
                        terminate(&mut child).await;
                        break (None, "deadline");
                    }
                    if flood_start.is_some_and(|t| now.saturating_sub(t) >= 5000) {
                        terminate(&mut child).await;
                        break (None, "output_flood");
                    }
                }
            }
        };
        input_task.abort();
        // Background processes can retain pipe FDs. Do not hang result persistence;
        // the systemd unit's control-group policy cleans them when this supervisor exits.
        let readers = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(&mut out, &mut err)
        })
        .await;
        let (stdout_bytes, stderr_bytes) = match readers {
            Ok((Ok(Ok(o)), Ok(Ok(e)))) => (o, e),
            _ => {
                out.abort();
                err.abort();
                // Join aborted readers before publishing the terminal frame:
                // detached readers must not append after Complete.
                if !out.is_finished() {
                    let _ = out.await;
                }
                if !err.is_finished() {
                    let _ = err.await;
                }
                truncated.store(true, Ordering::Relaxed);
                if framed {
                    (
                        stdout_completed.load(Ordering::Acquire),
                        stderr_completed.load(Ordering::Acquire),
                    )
                } else {
                    (
                        fs::metadata(directory.join("stdout"))
                            .map(|m| m.len())
                            .unwrap_or(0),
                        fs::metadata(directory.join("stderr"))
                            .map(|m| m.len())
                            .unwrap_or(0),
                    )
                }
            }
        };
        let result = RunnerResult {
            exit_code,
            reason: reason.into(),
            stdout_bytes,
            stderr_bytes,
            output_truncated: truncated.load(Ordering::Relaxed),
            finished_at_ms: unix_ms(),
        };
        write_new_json(&directory.join("result.json"), &result)?;
        Ok(result)
    }
}
