#![allow(missing_docs)]
//! Watcher implementation for Windows' directory management APIs
//!
//! For more information see the [ReadDirectoryChangesW reference][ref].
//!
//! [ref]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa363950(v=vs.85).aspx

use crate::{bounded, unbounded, BoundSender, Config, Receiver, Sender};
use crate::{event::*, WatcherKind};
use crate::{Error, EventHandler, RecursiveMode, Result, Watcher};
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use std::thread;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_OPERATION_ABORTED, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED,
    FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY,
    FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    CreateSemaphoreW, ReleaseSemaphore, WaitForSingleObjectEx, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIo, OVERLAPPED};

// Also sizes the kernel-side buffer where changes accumulate between reads; once that
// overflows, every buffered event is lost and the completion only reports that a rescan
// is needed (see `handle_event`). 64 KiB is the largest size that still works for
// directories watched over a network.
const BUF_SIZE: u32 = 65536;

#[derive(Clone)]
struct ReadData {
    dir: PathBuf,          // directory that is being watched
    file: Option<PathBuf>, // if a file is being watched, this is its full path
    complete_sem: HANDLE,
    is_recursive: bool,
}

struct ReadDirectoryRequest {
    event_handler: Arc<Mutex<dyn EventHandler>>,
    buffer: [u8; BUF_SIZE as usize],
    handle: HANDLE,
    data: ReadData,
}

enum Action {
    Watch(PathBuf, RecursiveMode),
    Unwatch(PathBuf),
    Stop,
    Configure(Config, BoundSender<Result<bool>>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MetaEvent {
    SingleWatchComplete,
    WatcherAwakened,
}

struct WatchState {
    dir_handle: HANDLE,
    complete_sem: HANDLE,
}

struct ReadDirectoryChangesServer {
    rx: Receiver<Action>,
    event_handler: Arc<Mutex<dyn EventHandler>>,
    meta_tx: Sender<MetaEvent>,
    cmd_tx: Sender<Result<PathBuf>>,
    watches: HashMap<PathBuf, WatchState>,
    wakeup_sem: HANDLE,
}

impl ReadDirectoryChangesServer {
    fn start(
        event_handler: Arc<Mutex<dyn EventHandler>>,
        meta_tx: Sender<MetaEvent>,
        cmd_tx: Sender<Result<PathBuf>>,
        wakeup_sem: HANDLE,
    ) -> Sender<Action> {
        let (action_tx, action_rx) = unbounded();
        // it is, in fact, ok to send the semaphore across threads
        let sem_temp = wakeup_sem as u64;
        let _ = thread::Builder::new()
            .name("notify-rs windows loop".to_string())
            .spawn(move || {
                let wakeup_sem = sem_temp as HANDLE;
                let server = ReadDirectoryChangesServer {
                    rx: action_rx,
                    event_handler,
                    meta_tx,
                    cmd_tx,
                    watches: HashMap::new(),
                    wakeup_sem,
                };
                server.run();
            });
        action_tx
    }

    fn run(mut self) {
        loop {
            // process all available actions first
            let mut stopped = false;

            while let Ok(action) = self.rx.try_recv() {
                match action {
                    Action::Watch(path, recursive_mode) => {
                        let res = self.add_watch(path, recursive_mode.is_recursive());
                        let _ = self.cmd_tx.send(res);
                    }
                    Action::Unwatch(path) => self.remove_watch(path),
                    Action::Stop => {
                        stopped = true;
                        for ws in self.watches.values() {
                            stop_watch(ws, &self.meta_tx);
                        }
                        break;
                    }
                    Action::Configure(config, tx) => {
                        self.configure_raw_mode(config, tx);
                    }
                }
            }

            if stopped {
                break;
            }

            unsafe {
                // wait with alertable flag so that the completion routine fires
                let waitres = WaitForSingleObjectEx(self.wakeup_sem, 100, 1);
                if waitres == WAIT_OBJECT_0 {
                    let _ = self.meta_tx.send(MetaEvent::WatcherAwakened);
                }
            }
        }

        // we have to clean this up, since the watcher may be long gone
        unsafe {
            CloseHandle(self.wakeup_sem);
        }
    }

    fn add_watch(&mut self, path: PathBuf, is_recursive: bool) -> Result<PathBuf> {
        // path must exist and be either a file or directory
        if !path.is_dir() && !path.is_file() {
            return Err(
                Error::generic("Input watch path is neither a file nor a directory.")
                    .add_path(path),
            );
        }

        let (watching_file, dir_target) = {
            if path.is_dir() {
                (false, path.clone())
            } else {
                // emulate file watching by watching the parent directory
                (true, path.parent().unwrap().to_path_buf())
            }
        };

        let encoded_path: Vec<u16> = dir_target
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle;
        unsafe {
            handle = CreateFileW(
                encoded_path.as_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                0,
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(if watching_file {
                    Error::generic(
                        "You attempted to watch a single file, but parent \
                         directory could not be opened.",
                    )
                    .add_path(path)
                } else {
                    // TODO: Call GetLastError for better error info?
                    Error::path_not_found().add_path(path)
                });
            }
        }
        let wf = if watching_file {
            Some(path.clone())
        } else {
            None
        };
        // every watcher gets its own semaphore to signal completion
        let semaphore = unsafe { CreateSemaphoreW(ptr::null_mut(), 0, 1, ptr::null_mut()) };
        if semaphore == 0 || semaphore == INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(handle);
            }
            return Err(Error::generic("Failed to create semaphore for watch.").add_path(path));
        }
        let rd = ReadData {
            dir: dir_target,
            file: wf,
            complete_sem: semaphore,
            is_recursive,
        };
        let ws = WatchState {
            dir_handle: handle,
            complete_sem: semaphore,
        };
        self.watches.insert(path.clone(), ws);
        start_read(&rd, self.event_handler.clone(), handle);
        Ok(path)
    }

    fn remove_watch(&mut self, path: PathBuf) {
        if let Some(ws) = self.watches.remove(&path) {
            stop_watch(&ws, &self.meta_tx);
        }
    }

    fn configure_raw_mode(&mut self, _config: Config, tx: BoundSender<Result<bool>>) {
        tx.send(Ok(false))
            .expect("configuration channel disconnect");
    }
}

fn stop_watch(ws: &WatchState, meta_tx: &Sender<MetaEvent>) {
    unsafe {
        let cio = CancelIo(ws.dir_handle);
        let ch = CloseHandle(ws.dir_handle);
        // have to wait for it, otherwise we leak the memory allocated for there read request
        if cio != 0 && ch != 0 {
            while WaitForSingleObjectEx(ws.complete_sem, INFINITE, 1) != WAIT_OBJECT_0 {
                // drain the apc queue, fix for https://github.com/notify-rs/notify/issues/287#issuecomment-801465550
            }
        }
        CloseHandle(ws.complete_sem);
    }
    let _ = meta_tx.send(MetaEvent::SingleWatchComplete);
}

fn start_read(rd: &ReadData, event_handler: Arc<Mutex<dyn EventHandler>>, handle: HANDLE) {
    let mut request = Box::new(ReadDirectoryRequest {
        event_handler,
        handle,
        buffer: [0u8; BUF_SIZE as usize],
        data: rd.clone(),
    });

    let flags = FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_ATTRIBUTES
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_CREATION
        | FILE_NOTIFY_CHANGE_SECURITY;

    let monitor_subdir = if (&request.data.file).is_none() && request.data.is_recursive {
        1
    } else {
        0
    };

    unsafe {
        let mut overlapped = std::mem::ManuallyDrop::new(Box::new(mem::zeroed::<OVERLAPPED>()));
        // When using callback based async requests, we are allowed to use the hEvent member
        // for our own purposes

        let req_buf = request.buffer.as_mut_ptr() as *mut c_void;
        let request_p = Box::into_raw(request) as isize;
        overlapped.hEvent = request_p;

        // This is using an asynchronous call with a completion routine for receiving notifications
        // An I/O completion port would probably be more performant
        let ret = ReadDirectoryChangesW(
            handle,
            req_buf,
            BUF_SIZE,
            monitor_subdir,
            flags,
            &mut 0u32 as *mut u32, // not used for async reqs
            (&mut **overlapped) as *mut OVERLAPPED,
            Some(handle_event),
        );

        if ret == 0 {
            // error reading. retransmute request memory to allow drop.
            // Because of the error, ownership of the `overlapped` alloc was not passed
            // over to `ReadDirectoryChangesW`.
            // So we can claim ownership back.
            let os_error = std::io::Error::last_os_error();
            let _overlapped_alloc = std::mem::ManuallyDrop::into_inner(overlapped);
            let request: Box<ReadDirectoryRequest> = Box::from_raw(request_p as *mut ReadDirectoryRequest);
            // Without a queued read this watch is dead: surface the failure so the
            // consumer learns events stopped flowing instead of a silent stop.
            let path = request
                .data
                .file
                .clone()
                .unwrap_or_else(|| request.data.dir.clone());
            if let Ok(mut guard) = request.event_handler.lock() {
                guard.handle_event(Err(Error::io(os_error).add_path(path)));
            }
            ReleaseSemaphore(request.data.complete_sem, 1, ptr::null_mut());
        }
    }
}

unsafe extern "system" fn handle_event(
    error_code: u32,
    bytes_written: u32,
    overlapped: *mut OVERLAPPED,
) {
    let overlapped: Box<OVERLAPPED> = Box::from_raw(overlapped);
    let request: Box<ReadDirectoryRequest> = Box::from_raw(overlapped.hEvent as *mut _);

    fn emit_event(event_handler: &Mutex<dyn EventHandler>, res: Result<Event>) {
        if let Ok(mut guard) = event_handler.lock() {
            let f: &mut dyn EventHandler = &mut *guard;
            f.handle_event(res);
        }
    }

    match error_code {
        ERROR_SUCCESS => {}
        ERROR_OPERATION_ABORTED => {
            // received when dir is unwatched or watcher is shutdown; return and let
            // overlapped/request get drop-cleaned
            ReleaseSemaphore(request.data.complete_sem, 1, ptr::null_mut());
            return;
        }
        // The watch handle was invalidated because the watched directory itself was
        // deleted (plain permission revocation keeps the directory visible and falls
        // through to the arm below). Report the removal for directory watches so
        // consumers can reconcile; a watched file's own FILE_ACTION_REMOVED arrives
        // through the parent-directory watch. No re-arm: reads on the dead handle can
        // only fail.
        ERROR_ACCESS_DENIED if matches!(request.data.dir.try_exists(), Ok(false)) => {
            if request.data.file.is_none() {
                let ev = Event::new(EventKind::Remove(RemoveKind::Folder))
                    .add_path(request.data.dir.clone());
                emit_event(&request.event_handler, Ok(ev));
            }
            ReleaseSemaphore(request.data.complete_sem, 1, ptr::null_mut());
            return;
        }
        // Any other failure means this watch stopped delivering events (e.g. the handle
        // went bad while the directory still exists). Surface it instead of dying
        // silently; the buffer contents are not valid on a failed completion, so do not
        // parse or re-arm.
        _ => {
            let path = request
                .data
                .file
                .clone()
                .unwrap_or_else(|| request.data.dir.clone());
            let err =
                Error::io(std::io::Error::from_raw_os_error(error_code as i32)).add_path(path);
            emit_event(&request.event_handler, Err(err));
            ReleaseSemaphore(request.data.complete_sem, 1, ptr::null_mut());
            return;
        }
    }

    // Get the next request queued up as soon as possible
    start_read(&request.data, request.event_handler.clone(), request.handle);

    // A successful completion with zero bytes means the kernel-side change buffer
    // overflowed before this read drained it: the OS discarded every event in that
    // window and asks us to rescan ourselves. Emit a rescan-flagged event carrying the
    // watch target so consumers can reconcile — deletions in the dropped window would
    // otherwise never be observed. (FSEvents and inotify report the same condition as
    // MustScanSubDirs / Q_OVERFLOW, which notify also maps to `Flag::Rescan`.)
    if bytes_written == 0 {
        let path = request
            .data
            .file
            .clone()
            .unwrap_or_else(|| request.data.dir.clone());
        let ev = Event::new(EventKind::Other)
            .set_flag(Flag::Rescan)
            .add_path(path);
        emit_event(&request.event_handler, Ok(ev));
        return;
    }

    // The FILE_NOTIFY_INFORMATION struct has a variable length due to the variable length
    // string as its last member. Each struct contains an offset for getting the next entry in
    // the buffer.
    let mut cur_offset: *const u8 = request.buffer.as_ptr();
    let mut cur_entry = cur_offset as *const FILE_NOTIFY_INFORMATION;
    loop {
        // filename length is size in bytes, so / 2
        let len = (*cur_entry).FileNameLength as usize / 2;
        let encoded_path: &[u16] = slice::from_raw_parts((*cur_entry).FileName.as_ptr(), len);
        // prepend root to get a full path
        let path = request
            .data
            .dir
            .join(PathBuf::from(OsString::from_wide(encoded_path)));

        // if we are watching a single file, ignore the event unless the path is exactly
        // the watched file
        let skip = match request.data.file {
            None => false,
            Some(ref watch_path) => *watch_path != path,
        };

        if !skip {
            log::trace!(
                "Event: path = `{}`, action = {:?}",
                path.display(),
                (*cur_entry).Action
            );

            let newe = Event::new(EventKind::Any).add_path(path);

            let event_handler = |res| emit_event(&request.event_handler, res);

            if (*cur_entry).Action == FILE_ACTION_RENAMED_OLD_NAME {
                let mode = RenameMode::From;
                let kind = ModifyKind::Name(mode);
                let kind = EventKind::Modify(kind);
                let ev = newe.set_kind(kind);
                event_handler(Ok(ev))
            } else {
                match (*cur_entry).Action {
                    FILE_ACTION_RENAMED_NEW_NAME => {
                        let kind = EventKind::Modify(ModifyKind::Name(RenameMode::To));
                        let ev = newe.set_kind(kind);
                        event_handler(Ok(ev));
                    }
                    FILE_ACTION_ADDED => {
                        let kind = EventKind::Create(CreateKind::Any);
                        let ev = newe.set_kind(kind);
                        event_handler(Ok(ev));
                    }
                    FILE_ACTION_REMOVED => {
                        let kind = EventKind::Remove(RemoveKind::Any);
                        let ev = newe.set_kind(kind);
                        event_handler(Ok(ev));
                    }
                    FILE_ACTION_MODIFIED => {
                        let kind = EventKind::Modify(ModifyKind::Any);
                        let ev = newe.set_kind(kind);
                        event_handler(Ok(ev));
                    }
                    _ => (),
                };
            }
        }

        if (*cur_entry).NextEntryOffset == 0 {
            break;
        }
        cur_offset = cur_offset.offset((*cur_entry).NextEntryOffset as isize);
        cur_entry = cur_offset as *const FILE_NOTIFY_INFORMATION;
    }
}

/// Watcher implementation based on ReadDirectoryChanges
#[derive(Debug)]
pub struct ReadDirectoryChangesWatcher {
    tx: Sender<Action>,
    cmd_rx: Receiver<Result<PathBuf>>,
    wakeup_sem: HANDLE,
}

impl ReadDirectoryChangesWatcher {
    pub fn create(
        event_handler: Arc<Mutex<dyn EventHandler>>,
        meta_tx: Sender<MetaEvent>,
    ) -> Result<ReadDirectoryChangesWatcher> {
        let (cmd_tx, cmd_rx) = unbounded();

        let wakeup_sem = unsafe { CreateSemaphoreW(ptr::null_mut(), 0, 1, ptr::null_mut()) };
        if wakeup_sem == 0 || wakeup_sem == INVALID_HANDLE_VALUE {
            return Err(Error::generic("Failed to create wakeup semaphore."));
        }

        let action_tx =
            ReadDirectoryChangesServer::start(event_handler, meta_tx, cmd_tx, wakeup_sem);

        Ok(ReadDirectoryChangesWatcher {
            tx: action_tx,
            cmd_rx,
            wakeup_sem,
        })
    }

    fn wakeup_server(&mut self) {
        // breaks the server out of its wait state.  right now this is really just an optimization,
        // so that if you add a watch you don't block for 100ms in watch() while the
        // server sleeps.
        unsafe {
            ReleaseSemaphore(self.wakeup_sem, 1, ptr::null_mut());
        }
    }

    fn send_action_require_ack(&mut self, action: Action, pb: &PathBuf) -> Result<()> {
        self.tx
            .send(action)
            .map_err(|_| Error::generic("Error sending to internal channel"))?;

        // wake 'em up, we don't want to wait around for the ack
        self.wakeup_server();

        let ack_pb = self
            .cmd_rx
            .recv()
            .map_err(|_| Error::generic("Error receiving from command channel"))?
            .map_err(|e| Error::generic(&format!("Error in watcher: {:?}", e)))?;

        if pb.as_path() != ack_pb.as_path() {
            Err(Error::generic(&format!(
                "Expected ack for {:?} but got \
                 ack for {:?}",
                pb, ack_pb
            )))
        } else {
        Ok(())
        }
    }

    fn watch_inner(&mut self, path: &Path, recursive_mode: RecursiveMode) -> Result<()> {
        let pb = if path.is_absolute() {
            path.to_owned()
        } else {
            let p = env::current_dir().map_err(Error::io)?;
            p.join(path)
        };
        // path must exist and be either a file or directory
        if !pb.is_dir() && !pb.is_file() {
            return Err(Error::generic(
                "Input watch path is neither a file nor a directory.",
            ));
        }
        self.send_action_require_ack(Action::Watch(pb.clone(), recursive_mode), &pb)
    }

    fn unwatch_inner(&mut self, path: &Path) -> Result<()> {
        let pb = if path.is_absolute() {
            path.to_owned()
        } else {
            let p = env::current_dir().map_err(Error::io)?;
            p.join(path)
        };
        let res = self
            .tx
            .send(Action::Unwatch(pb))
            .map_err(|_| Error::generic("Error sending to internal channel"));
        self.wakeup_server();
        res
    }
}

impl Watcher for ReadDirectoryChangesWatcher {
    fn new<F: EventHandler>(event_handler: F, _config: Config) -> Result<Self> {
        // create dummy channel for meta event
        // TODO: determine the original purpose of this - can we remove it?
        let (meta_tx, _) = unbounded();
        let event_handler = Arc::new(Mutex::new(event_handler));
        Self::create(event_handler, meta_tx)
    }

    fn watch(&mut self, path: &Path, recursive_mode: RecursiveMode) -> Result<()> {
        self.watch_inner(path, recursive_mode)
    }

    fn unwatch(&mut self, path: &Path) -> Result<()> {
        self.unwatch_inner(path)
    }

    fn configure(&mut self, config: Config) -> Result<bool> {
        let (tx, rx) = bounded(1);
        self.tx.send(Action::Configure(config, tx))?;
        rx.recv()?
    }

    fn kind() -> crate::WatcherKind {
        WatcherKind::ReadDirectoryChangesWatcher
    }
}

impl Drop for ReadDirectoryChangesWatcher {
    fn drop(&mut self) {
        let _ = self.tx.send(Action::Stop);
        // better wake it up
        self.wakeup_server();
    }
}

// `ReadDirectoryChangesWatcher` is not Send/Sync because of the semaphore Handle.
// As said elsewhere it's perfectly safe to send it across threads.
unsafe impl Send for ReadDirectoryChangesWatcher {}
// Because all public methods are `&mut self` it's also perfectly safe to share references.
unsafe impl Sync for ReadDirectoryChangesWatcher {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn recv_matching(
        rx: &mpsc::Receiver<Result<Event>>,
        timeout: Duration,
        pred: impl Fn(&Result<Event>) -> bool,
    ) -> Option<Result<Event>> {
        let deadline = Instant::now() + timeout;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(remaining) {
                Ok(res) if pred(&res) => return Some(res),
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        None
    }

    #[test]
    fn create_and_remove_events_are_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let mut watcher = ReadDirectoryChangesWatcher::new(
            move |res: Result<Event>| {
                let _ = tx.send(res);
            },
            Config::default(),
        )
        .unwrap();
        watcher.watch(dir.path(), RecursiveMode::Recursive).unwrap();

        let file = dir.path().join("a.txt");
        fs::write(&file, b"x").unwrap();
        assert!(
            recv_matching(&rx, Duration::from_secs(10), |res| matches!(
                res,
                Ok(ev) if matches!(ev.kind, EventKind::Create(_)) && ev.paths.contains(&file)
            ))
            .is_some(),
            "expected a Create event for {file:?}"
        );

        fs::remove_file(&file).unwrap();
        assert!(
            recv_matching(&rx, Duration::from_secs(10), |res| matches!(
                res,
                Ok(ev) if matches!(ev.kind, EventKind::Remove(_)) && ev.paths.contains(&file)
            ))
            .is_some(),
            "expected a Remove event for {file:?}"
        );
    }

    // The kernel accumulates changes for a watch in a BUF_SIZE-byte buffer between reads;
    // when it overflows, the read completes with zero bytes and every buffered event is
    // lost. Guards the fix: that condition must surface as a `Flag::Rescan` event carrying
    // the watch root — previously it was silently swallowed, so consumers (e.g. a file
    // index) never learned that deletions were dropped.
    #[test]
    fn buffer_overflow_emits_rescan_event() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let gate = Arc::new(AtomicBool::new(false));
        let blocked = Arc::new(AtomicBool::new(false));
        let handler_gate = gate.clone();
        let handler_blocked = blocked.clone();

        let mut watcher = ReadDirectoryChangesWatcher::new(
            move |res: Result<Event>| {
                // Park the completion-routine thread on the first event so the kernel
                // buffer fills (and overflows) behind it.
                if !handler_blocked.swap(true, Ordering::SeqCst) {
                    let deadline = Instant::now() + Duration::from_secs(30);
                    while !handler_gate.load(Ordering::SeqCst) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                let _ = tx.send(res);
            },
            Config::default(),
        )
        .unwrap();
        watcher.watch(dir.path(), RecursiveMode::Recursive).unwrap();

        // First change parks the handler...
        fs::write(dir.path().join("gate-opener"), b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !blocked.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "watcher never delivered the first event");
            std::thread::sleep(Duration::from_millis(5));
        }

        // ...then generate far more change records than BUF_SIZE can hold.
        for i in 0..8000 {
            let path = dir
                .path()
                .join(format!("overflow-file-{i:05}-padding-padding-padding.tmp"));
            fs::write(&path, b"").unwrap();
        }
        gate.store(true, Ordering::SeqCst);

        let rescan = recv_matching(&rx, Duration::from_secs(30), |res| {
            matches!(res, Ok(ev) if ev.need_rescan())
        })
        .expect("kernel buffer overflow must surface as a rescan event");
        let rescan = rescan.unwrap();
        assert_eq!(rescan.kind, EventKind::Other);
        assert_eq!(rescan.paths, vec![dir.path().to_path_buf()]);
    }

    // Deleting the watched directory itself invalidates the watch handle. Guards against
    // the watch dying silently: the consumer must observe either a Remove event for the
    // root (handle already invalidated) or an error — anything but silence.
    #[test]
    fn deleting_watched_directory_is_surfaced() {
        let parent = tempfile::tempdir().unwrap();
        let watched = parent.path().join("watched");
        fs::create_dir(&watched).unwrap();

        let (tx, rx) = mpsc::channel();
        let mut watcher = ReadDirectoryChangesWatcher::new(
            move |res: Result<Event>| {
                let _ = tx.send(res);
            },
            Config::default(),
        )
        .unwrap();
        watcher.watch(&watched, RecursiveMode::Recursive).unwrap();

        fs::remove_dir_all(&watched).unwrap();

        let surfaced = recv_matching(&rx, Duration::from_secs(10), |res| match res {
            Ok(ev) => matches!(ev.kind, EventKind::Remove(_)) && ev.paths.contains(&watched),
            Err(_) => true,
        });
        assert!(
            surfaced.is_some(),
            "deleting the watched directory must surface a Remove event or an error, not silence"
        );
    }
}
