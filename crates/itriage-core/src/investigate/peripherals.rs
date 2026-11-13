//! Peripheral drops during a recording: when a device the site profile
//! requires (`[[require.device]]`: the barcode scanner, the badge reader,
//! the signature pad) disappears and comes back, each is timestamped as a
//! marker in the capture.
//!
//! Windows registers for device-instance notifications (CM_Register_
//! Notification); Linux listens to the kernel's uevents on a netlink socket.
//! Either way the device list is also re-read every few seconds, so a
//! missed notification can't hide a drop. Notifications carry only an
//! instance id; the names come from the device list, which is why a device
//! is tracked by id once it's been seen.

use crate::investigate::recording::{Marker, MAX_DEVICE_MARKERS};
use crate::profile::DeviceReq;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// One change to a watched device.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub at_ms: u64,
    pub arrived: bool,
    /// The requirement's label ("Badge reader").
    pub label: String,
    /// The device's own name.
    pub name: String,
}

impl Change {
    pub fn marker(&self) -> Marker {
        Marker {
            at_ms: self.at_ms,
            label: format!("{} {}: {}", self.label, if self.arrived { "back" } else { "dropped" }, self.name),
            device: Some(crate::investigate::recording::DeviceMark { label: self.label.clone(), name: self.name.clone(), arrived: self.arrived }),
        }
    }
}

struct Known {
    name: String,
    label: String,
    present: bool,
}

/// Which watched devices are present, from device lists and notifications.
pub struct Tracker {
    watched: Vec<(String, String)>,
    known: HashMap<String, Known>,
    started: bool,
    last: Vec<Change>,
}

/// Two changes to the same device and direction this close together are
/// one (a USB device and its HID child both matching, say).
const SAME_MS: u64 = 2_000;

impl Tracker {
    pub fn new(reqs: &[DeviceReq]) -> Self {
        Tracker {
            watched: reqs.iter().filter(|r| !r.pattern.trim().is_empty()).map(|r| (r.label.clone(), r.pattern.trim().to_lowercase())).collect(),
            known: HashMap::new(),
            started: false,
            last: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.watched.is_empty()
    }

    fn label_for(&self, name: &str) -> Option<String> {
        let lower = name.to_lowercase();
        self.watched.iter().find(|(_, p)| lower.contains(p)).map(|(l, _)| l.clone())
    }

    fn emit(&mut self, at_ms: u64, arrived: bool, label: &str, name: &str) -> Option<Change> {
        let duplicate = self.last.iter().rev().any(|c| c.label == label && c.arrived == arrived && at_ms.abs_diff(c.at_ms) < SAME_MS);
        if duplicate {
            return None;
        }
        let change = Change { at_ms, arrived, label: label.to_string(), name: name.to_string() };
        self.last.push(change.clone());
        if self.last.len() > 32 {
            self.last.remove(0);
        }
        Some(change)
    }

    /// A fresh list of present devices (id, name). The first list sets the
    /// starting point; later ones report what came and went since.
    pub fn observe(&mut self, present: &[(String, String)], at_ms: u64) -> Vec<Change> {
        let mut out = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for (id, name) in present {
            let Some(label) = self.label_for(name) else { continue };
            let id = id.to_ascii_uppercase();
            seen.push(id.clone());
            match self.known.get_mut(&id) {
                Some(k) if !k.present => {
                    k.present = true;
                    let (label, name) = (k.label.clone(), k.name.clone());
                    out.extend(self.emit(at_ms, true, &label, &name));
                }
                Some(_) => {}
                None => {
                    self.known.insert(id, Known { name: name.clone(), label: label.clone(), present: true });
                    if self.started {
                        out.extend(self.emit(at_ms, true, &label, name));
                    }
                }
            }
        }
        let gone: Vec<(String, String)> = self
            .known
            .iter_mut()
            .filter(|(id, k)| k.present && !seen.contains(id))
            .map(|(_, k)| {
                k.present = false;
                (k.label.clone(), k.name.clone())
            })
            .collect();
        for (label, name) in gone {
            out.extend(self.emit(at_ms, false, &label, &name));
        }
        self.started = true;
        out
    }

    /// A notification about one device instance. Only devices already seen
    /// are reported here; a new one is picked up by the next list.
    pub fn notify(&mut self, id: &str, arrived: bool, at_ms: u64) -> Option<Change> {
        let k = self.known.get_mut(&id.to_ascii_uppercase())?;
        if k.present == arrived {
            return None;
        }
        k.present = arrived;
        let (label, name) = (k.label.clone(), k.name.clone());
        self.emit(at_ms, arrived, &label, &name)
    }
}

/// A kernel uevent's action and device path, for USB devices only
/// (`add@/devices/…` then `KEY=value` lines, NUL-separated).
pub fn parse_uevent(buf: &[u8]) -> Option<(bool, String)> {
    let text = String::from_utf8_lossy(buf);
    let mut parts = text.split('\0');
    let head = parts.next()?;
    let (action, _) = head.split_once('@')?;
    let mut subsystem = "";
    let mut devtype = "";
    let mut devpath = "";
    for p in parts {
        if let Some(v) = p.strip_prefix("SUBSYSTEM=") {
            subsystem = v;
        } else if let Some(v) = p.strip_prefix("DEVTYPE=") {
            devtype = v;
        } else if let Some(v) = p.strip_prefix("DEVPATH=") {
            devpath = v;
        }
    }
    if subsystem != "usb" || devtype != "usb_device" || devpath.is_empty() {
        return None;
    }
    match action {
        "add" | "bind" => Some((true, devpath.to_string())),
        "remove" | "unbind" => Some((false, devpath.to_string())),
        _ => None,
    }
}

/// A notification from the OS: a device instance (Windows) or USB device
/// path (Linux) arrived or went.
type Note = (u64, bool, String);

/// Watch the profile's devices until `stop`, adding a marker to `markers`
/// for each drop and return. Returns a coverage gap to report, if the
/// notifications couldn't be set up.
pub fn watch(reqs: &[DeviceReq], markers: &Mutex<Vec<Marker>>, stop: &AtomicBool) -> Option<String> {
    let mut tracker = Tracker::new(reqs);
    if tracker.is_empty() {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::channel::<Note>();
    let (subscription, gap) = match os::subscribe(tx) {
        Ok(s) => (Some(s), None),
        Err(e) => (None, Some(format!("Device notifications weren't available ({e}); required devices were checked every {} seconds instead, so a shorter drop could be missed.", POLL.as_secs()))),
    };
    let mut added = 0usize;
    let mut push = |changes: Vec<Change>| {
        if changes.is_empty() {
            return;
        }
        if let Ok(mut rows) = markers.lock() {
            for c in changes {
                if added < MAX_DEVICE_MARKERS {
                    rows.push(c.marker());
                    added += 1;
                }
            }
        }
    };
    push(tracker.observe(&os::present(), crate::investigate::recording::now_ms()));
    let mut last_list = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok((at, arrived, id)) => {
                let mut changes: Vec<Change> = tracker.notify(&id, arrived, at).into_iter().collect();
                // An arrival may be a device not seen before: the list says
                // what it is, once it has settled.
                if arrived {
                    std::thread::sleep(Duration::from_millis(300));
                    while let Ok((at, arrived, id)) = rx.try_recv() {
                        changes.extend(tracker.notify(&id, arrived, at));
                    }
                    changes.extend(tracker.observe(&os::present(), at));
                    last_list = std::time::Instant::now();
                }
                push(changes);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::thread::sleep(Duration::from_millis(250)),
        }
        if last_list.elapsed() >= POLL {
            push(tracker.observe(&os::present(), crate::investigate::recording::now_ms()));
            last_list = std::time::Instant::now();
        }
    }
    drop(subscription);
    gap
}

const POLL: Duration = Duration::from_secs(3);

#[cfg(windows)]
mod os {
    use super::Note;
    use std::sync::mpsc::Sender;
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Register_Notification, CM_Unregister_Notification, CM_NOTIFY_ACTION, CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED,
        CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED, CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED, CM_NOTIFY_EVENT_DATA, CM_NOTIFY_FILTER,
        CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES, CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, CR_SUCCESS, HCMNOTIFICATION,
    };

    pub fn present() -> Vec<(String, String)> {
        crate::win::devices::present().map(|d| d.into_iter().map(|d| (d.instance_id, d.name)).collect()).unwrap_or_default()
    }

    /// Unregisters on drop, then frees the sender the callback used.
    pub struct Subscription {
        handle: HCMNOTIFICATION,
        context: *mut Sender<Note>,
    }

    impl Drop for Subscription {
        fn drop(&mut self) {
            // SAFETY: unregistering waits for callbacks in progress, so the
            // context is no longer in use when it's freed.
            unsafe {
                let _ = CM_Unregister_Notification(self.handle);
                drop(Box::from_raw(self.context));
            }
        }
    }

    unsafe extern "system" fn callback(
        _h: HCMNOTIFICATION,
        context: *const core::ffi::c_void,
        action: CM_NOTIFY_ACTION,
        data: *const CM_NOTIFY_EVENT_DATA,
        size: u32,
    ) -> u32 {
        let arrived = match action {
            CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED | CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED => true,
            CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED => false,
            _ => return 0,
        };
        if context.is_null() || data.is_null() {
            return 0;
        }
        // The instance id runs from the union to the end of the event data,
        // NUL-terminated.
        let offset = std::mem::offset_of!(CM_NOTIFY_EVENT_DATA, u);
        let units = (size as usize).saturating_sub(offset) / 2;
        let start = std::ptr::addr_of!((*data).u.DeviceInstance.InstanceId) as *const u16;
        let wide = std::slice::from_raw_parts(start, units);
        let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        let id = String::from_utf16_lossy(&wide[..end]);
        let tx = &*(context as *const Sender<Note>);
        let _ = tx.send((crate::investigate::recording::now_ms(), arrived, id));
        0
    }

    pub fn subscribe(tx: Sender<Note>) -> Result<Subscription, String> {
        let context = Box::into_raw(Box::new(tx));
        let filter = CM_NOTIFY_FILTER {
            cbSize: std::mem::size_of::<CM_NOTIFY_FILTER>() as u32,
            Flags: CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES,
            FilterType: CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE,
            ..Default::default()
        };
        let mut handle = HCMNOTIFICATION::default();
        // SAFETY: the filter is a live local; the context outlives the
        // registration (Subscription frees it after unregistering).
        let rc = unsafe { CM_Register_Notification(&filter, Some(context as *const _), Some(callback), &mut handle) };
        if rc != CR_SUCCESS {
            // SAFETY: not registered, so nothing else holds the context.
            unsafe { drop(Box::from_raw(context)) };
            return Err(format!("CM_Register_Notification failed ({})", rc.0));
        }
        Ok(Subscription { handle, context })
    }
}

#[cfg(target_os = "linux")]
mod os {
    use super::Note;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::Sender;
    use std::sync::Arc;

    /// USB devices from sysfs: (device path as uevents name it, name).
    pub fn present() -> Vec<(String, String)> {
        crate::desk::devices::usb_devices_with_paths()
    }

    pub struct Subscription {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for Subscription {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            // SAFETY: a descriptor this struct owns, closed once.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    pub fn subscribe(tx: Sender<Note>) -> Result<Subscription, String> {
        // SAFETY: plain socket calls on a descriptor owned by `Fd`; the
        // address and timeout are live locals of the sizes passed.
        let fd = unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_KOBJECT_UEVENT);
            if fd < 0 {
                return Err(format!("netlink socket: {}", std::io::Error::last_os_error()));
            }
            let fd = Fd(fd);
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_groups = 1; // the kernel's own uevents
            if libc::bind(fd.0, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) != 0 {
                return Err(format!("netlink bind: {}", std::io::Error::last_os_error()));
            }
            let timeout = libc::timeval { tv_sec: 0, tv_usec: 250_000 };
            // Without the timeout a read would never return, and the reader
            // thread could never be told to stop.
            if libc::setsockopt(fd.0, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &timeout as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32) != 0 {
                return Err(format!("netlink timeout: {}", std::io::Error::last_os_error()));
            }
            fd
        };
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; 16 * 1024];
            while !flag.load(Ordering::Relaxed) {
                // SAFETY: reads into a live buffer of the length passed.
                let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n <= 0 {
                    // The timeout (or a signal) just means look at the stop
                    // flag again. Anything else would come straight back:
                    // wait a moment instead of spinning on it.
                    let kind = std::io::Error::last_os_error().kind();
                    if n < 0 && !matches!(kind, std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    continue;
                }
                if let Some((arrived, path)) = super::parse_uevent(&buf[..n as usize]) {
                    if tx.send((crate::investigate::recording::now_ms(), arrived, path)).is_err() {
                        break;
                    }
                }
            }
        });
        Ok(Subscription { stop, thread: Some(thread) })
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod os {
    use super::Note;
    pub struct Subscription;
    pub fn present() -> Vec<(String, String)> {
        Vec::new()
    }
    pub fn subscribe(_tx: std::sync::mpsc::Sender<Note>) -> Result<Subscription, String> {
        Err("not supported on this system".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reqs() -> Vec<DeviceReq> {
        vec![DeviceReq { label: "Scanner".into(), pattern: "Xenon".into() }, DeviceReq { label: "Badge reader".into(), pattern: "pcProx".into() }]
    }

    fn list(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn drops_and_returns_are_reported_once_each() {
        let mut t = Tracker::new(&reqs());
        let start = list(&[(r"USB\VID_0C2E&PID_0B61\1", "Honeywell Xenon 1950g"), (r"HID\VID_0C2E&PID_0B61&MI_00\7&1", "Xenon HID"), (r"USB\VID_0C27&PID_3BFA\2", "RFIDeas pcProx USB"), (r"USB\VID_046D\3", "Mouse")]);
        assert!(t.observe(&start, 1_000).is_empty(), "the first list is the starting point");
        // Unplug: both of the scanner's nodes go; one drop.
        let gone = t.notify(r"usb\vid_0c2e&pid_0b61\1", false, 5_000).unwrap();
        assert_eq!((gone.label.as_str(), gone.arrived, gone.name.as_str()), ("Scanner", false, "Honeywell Xenon 1950g"));
        assert!(t.notify(r"HID\VID_0C2E&PID_0B61&MI_00\7&1", false, 5_010).is_none(), "its HID child is the same drop");
        assert!(t.notify(r"USB\VID_046D\3", false, 5_020).is_none(), "an unwatched device is ignored");
        assert!(t.notify(r"USB\VID_0C2E&PID_0B61\1", false, 5_500).is_none(), "already gone");
        // A list read while it's still out changes nothing.
        let without = list(&[(r"USB\VID_0C27&PID_3BFA\2", "RFIDeas pcProx USB")]);
        assert!(t.observe(&without, 6_000).is_empty());
        // Back, in a list (no notification).
        let back = t.observe(&start, 9_000);
        assert_eq!(back.len(), 1);
        assert!(back[0].arrived && back[0].label == "Scanner");
        assert_eq!(back[0].marker().label, "Scanner back: Honeywell Xenon 1950g");
    }

    #[test]
    fn a_device_first_seen_later_and_a_missed_notification_are_caught_by_the_list() {
        let mut t = Tracker::new(&reqs());
        t.observe(&list(&[(r"USB\VID_046D\3", "Mouse")]), 0);
        let arrived = t.observe(&list(&[(r"USB\VID_0C27&PID_3BFA\2", "RFIDeas pcProx USB")]), 3_000);
        assert_eq!(arrived.len(), 1);
        assert!(arrived[0].arrived && arrived[0].label == "Badge reader");
        let dropped = t.observe(&[], 6_000);
        assert_eq!(dropped.len(), 1);
        assert!(!dropped[0].arrived);
        assert!(Tracker::new(&[]).is_empty());
    }

    #[test]
    fn reads_usb_uevents_and_skips_the_rest() {
        let add = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-2\0ACTION=add\0DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-2\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0PRODUCT=c2e/b61/100\0";
        assert_eq!(parse_uevent(add), Some((true, "/devices/pci0000:00/0000:00:14.0/usb1/1-2".into())));
        let iface = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0\0ACTION=add\0DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0\0SUBSYSTEM=usb\0DEVTYPE=usb_interface\0";
        assert_eq!(parse_uevent(iface), None, "interfaces are part of their device");
        let remove = b"remove@/devices/x/usb1/1-2\0ACTION=remove\0DEVPATH=/devices/x/usb1/1-2\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0";
        assert_eq!(parse_uevent(remove), Some((false, "/devices/x/usb1/1-2".into())));
        assert_eq!(parse_uevent(b"libudev\0garbage"), None);
        assert_eq!(parse_uevent(b"change@/devices/x\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0DEVPATH=/devices/x\0"), None);
    }
}
