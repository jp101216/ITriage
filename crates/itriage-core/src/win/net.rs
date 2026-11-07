//! IP Helper and WinHTTP: adapters with their addresses, gateways and DNS
//! servers; the route Windows would pick for a destination (what
//! `Find-NetRoute` reports); ICMP echo; and an HTTPS GET that goes through
//! the system proxy settings, like `Invoke-RestMethod`.

use crate::net::{IfAddr, Interface, Route};
use crate::parse::net::AddrOrigin;
use crate::parse::ping::PingStats;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetBestRoute2, Icmp6CreateFile, Icmp6ParseReplies, Icmp6SendEcho2, IcmpCloseHandle,
    IcmpCreateFile, IcmpSendEcho, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    ICMPV6_ECHO_REPLY_LH, ICMP_ECHO_REPLY, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, IP_SUCCESS,
    MIB_IPFORWARD_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData,
    WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOCKADDR_INET, SOCKET_ADDRESS,
};

/// The address in a SOCKET_ADDRESS.
///
/// # Safety
/// `sa.lpSockaddr` must be null or point at a valid SOCKADDR of its family.
unsafe fn socket_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if sa.lpSockaddr.is_null() {
        return None;
    }
    let family = (*sa.lpSockaddr).sa_family;
    if family == AF_INET {
        let b = (*(sa.lpSockaddr as *const SOCKADDR_IN)).sin_addr.S_un.S_un_b;
        Some(IpAddr::V4(Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4)))
    } else if family == AF_INET6 {
        Some(IpAddr::V6(Ipv6Addr::from((*(sa.lpSockaddr as *const SOCKADDR_IN6)).sin6_addr.u.Byte)))
    } else {
        None
    }
}

/// # Safety
/// `s` must hold a valid address of the family in `si_family`.
unsafe fn inet_ip(s: &SOCKADDR_INET) -> Option<IpAddr> {
    if s.si_family == AF_INET {
        let b = s.Ipv4.sin_addr.S_un.S_un_b;
        Some(IpAddr::V4(Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4)))
    } else if s.si_family == AF_INET6 {
        Some(IpAddr::V6(Ipv6Addr::from(s.Ipv6.sin6_addr.u.Byte)))
    } else {
        None
    }
}

fn inet(ip: IpAddr, scope: u32) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(v4) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(v6) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: scope },
            },
        },
    }
}

/// Windows lists these deprecated site-local defaults as DNS servers on
/// adapters with no IPv6 DNS configured; nothing answers there.
fn is_placeholder_dns(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfec0)
}

pub fn interfaces() -> Result<Vec<Interface>, String> {
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
    let mut size = 32 * 1024u32;
    // SAFETY: the u64-backed buffer is sized from the API's report and stays
    // alive while the linked lists inside it are walked.
    unsafe {
        let mut backing: Vec<u64>;
        loop {
            backing = vec![0u64; size as usize / 8 + 1];
            let head = backing.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let rc = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(head), &mut size);
            if rc == 0 {
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                return Err(format!("can't list network adapters (error {rc})"));
            }
        }
        let mut out = Vec::new();
        let mut node = backing.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !node.is_null() {
            let a = &*node;
            let mut addresses = Vec::new();
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                if let Some(ip) = socket_ip(&(*u).Address) {
                    addresses.push(IfAddr {
                        ip,
                        prefix: (*u).OnLinkPrefixLength,
                        origin: AddrOrigin::from_windows((*u).PrefixOrigin.0),
                    });
                }
                u = (*u).Next;
            }
            let mut gateways = Vec::new();
            let mut g = a.FirstGatewayAddress;
            while !g.is_null() {
                gateways.extend(socket_ip(&(*g).Address));
                g = (*g).Next;
            }
            let mut dns_servers = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                if let Some(ip) = socket_ip(&(*d).Address).filter(|ip| !is_placeholder_dns(ip)) {
                    dns_servers.push(ip);
                }
                d = (*d).Next;
            }
            let v4_index = a.Anonymous1.Anonymous.IfIndex;
            out.push(Interface {
                index: if v4_index != 0 { v4_index } else { a.Ipv6IfIndex },
                name: a.FriendlyName.to_string().unwrap_or_default(),
                description: a.Description.to_string().unwrap_or_default(),
                up: a.OperStatus == IfOperStatusUp,
                loopback: a.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                addresses,
                gateways,
                dns_servers,
            });
            node = a.Next;
        }
        Ok(out)
    }
}

/// The adapter that owns an interface index (IPv4 and IPv6 indexes are the
/// same on modern Windows, but check both).
fn adapter_for(index: u32) -> Option<Interface> {
    interfaces().ok()?.into_iter().find(|i| i.index == index)
}

pub fn route_to(dest: IpAddr) -> Result<Route, String> {
    let destination = inet(dest, 0);
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: all pointers are to live locals of the right types.
    let rc = unsafe { GetBestRoute2(None, 0, None, &destination, 0, &mut row, &mut source) };
    if rc.0 != 0 {
        return Err(format!("Windows returned no usable route to {dest} (error {})", rc.0));
    }
    // SAFETY: GetBestRoute2 filled both with addresses of their families.
    let (next_hop, source) = unsafe { (inet_ip(&row.NextHop), inet_ip(&source)) };
    let next_hop = next_hop.filter(|ip| !ip.is_unspecified());
    let adapter = adapter_for(row.InterfaceIndex);
    Ok(Route {
        interface: adapter.as_ref().map(|a| a.name.clone()),
        index: Some(row.InterfaceIndex),
        source,
        next_hop,
        dns_servers: adapter.map(|a| a.dns_servers).unwrap_or_default(),
    })
}

pub fn ping(addr: IpAddr, scope: Option<u32>, count: u32, timeout: Duration) -> Result<PingStats, String> {
    const PAYLOAD: [u8; 32] = *b"abcdefghijklmnopqrstuvwabcdefghi";
    let timeout_ms = timeout.as_millis().clamp(1, 60_000) as u32;
    let mut rtts = Vec::new();
    // SAFETY: the handle is closed on every path; reply buffers are sized
    // for one reply plus the echoed payload and some headroom, as the API asks.
    unsafe {
        match addr {
            IpAddr::V4(v4) => {
                let handle = IcmpCreateFile().map_err(|e| crate::win::err("can't open ICMP", &e))?;
                let dest = u32::from_ne_bytes(v4.octets());
                let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 64];
                for _ in 0..count {
                    let n = IcmpSendEcho(
                        handle,
                        dest,
                        PAYLOAD.as_ptr() as *const _,
                        PAYLOAD.len() as u16,
                        None,
                        reply.as_mut_ptr() as *mut _,
                        reply.len() as u32,
                        timeout_ms,
                    );
                    if n > 0 {
                        let r = &*(reply.as_ptr() as *const ICMP_ECHO_REPLY);
                        if r.Status == IP_SUCCESS {
                            rtts.push(f64::from(r.RoundTripTime));
                        }
                    }
                }
                let _ = IcmpCloseHandle(handle);
            }
            IpAddr::V6(_) => {
                let handle = Icmp6CreateFile().map_err(|e| crate::win::err("can't open ICMPv6", &e))?;
                let any = inet(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
                let dest = inet(addr, scope.unwrap_or(0));
                let mut reply = vec![0u8; std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + PAYLOAD.len() + 64];
                for _ in 0..count {
                    let n = Icmp6SendEcho2(
                        handle,
                        None,
                        None,
                        None,
                        &any.Ipv6,
                        &dest.Ipv6,
                        PAYLOAD.as_ptr() as *const _,
                        PAYLOAD.len() as u16,
                        None,
                        reply.as_mut_ptr() as *mut _,
                        reply.len() as u32,
                        timeout_ms,
                    );
                    if n > 0 && Icmp6ParseReplies(reply.as_mut_ptr() as *mut _, reply.len() as u32) > 0 {
                        let r = &*(reply.as_ptr() as *const ICMPV6_ECHO_REPLY_LH);
                        if r.Status == IP_SUCCESS {
                            rtts.push(f64::from(r.RoundTripTime));
                        }
                    }
                }
                let _ = IcmpCloseHandle(handle);
            }
        }
    }
    Ok(PingStats::from_samples(count, &rtts))
}

/// Closes a WinHTTP handle when dropped.
struct Handle(*mut core::ffi::c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a handle WinHTTP gave us, closed once.
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

/// GET an https:// URL through the system proxy configuration (automatic
/// proxy on Windows 8.1+, falling back to the WinHTTP default).
pub fn http_get(url: &str, timeout: Duration) -> Result<String, String> {
    let rest = url.strip_prefix("https://").ok_or("only https:// URLs are fetched")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse().unwrap_or(443)),
        _ => (host, 443),
    };
    let ms = timeout.as_millis().clamp(500, 60_000) as i32;
    let fail = |what: &str, e: windows::core::Error| crate::win::err(&format!("{host}: {what}"), &e);
    // SAFETY: each handle is wrapped so it's closed on every path; buffers
    // passed to WinHTTP are live locals.
    unsafe {
        let mut session = Handle(WinHttpOpen(
            &HSTRING::from("itriage"),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ));
        if session.0.is_null() {
            session = Handle(WinHttpOpen(
                &HSTRING::from("itriage"),
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            ));
        }
        if session.0.is_null() {
            return Err(format!("{host}: WinHTTP isn't available"));
        }
        WinHttpSetTimeouts(session.0, ms, ms, ms, ms).map_err(|e| fail("setting timeouts", e))?;
        let connect = Handle(WinHttpConnect(session.0, &HSTRING::from(host), port, 0));
        if connect.0.is_null() {
            return Err(format!("{host}: couldn't connect"));
        }
        let request = Handle(WinHttpOpenRequest(
            connect.0,
            &HSTRING::from("GET"),
            &HSTRING::from(path),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null() {
            return Err(format!("{host}: couldn't open the request"));
        }
        WinHttpSendRequest(request.0, None, None, 0, 0, 0).map_err(|e| fail("request failed", e))?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut()).map_err(|e| fail("no response", e))?;
        let mut status = 0u32;
        let mut len = 4u32;
        let mut index = 0u32;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut _),
            &mut len,
            &mut index,
        )
        .map_err(|e| fail("reading the status", e))?;
        if status != 200 {
            return Err(format!("{host} answered HTTP {status}"));
        }
        let mut body = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let mut read = 0u32;
            WinHttpReadData(request.0, chunk.as_mut_ptr() as *mut _, chunk.len() as u32, &mut read)
                .map_err(|e| fail("reading the response", e))?;
            if read == 0 || body.len() > 64 * 1024 {
                break;
            }
            body.extend_from_slice(&chunk[..read as usize]);
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}
