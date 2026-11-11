//! DNS, direct-route TCP and application HTTP/TLS evidence. A direct TCP
//! failure is not proof the application is down: its proxy may still work.
use crate::model::{Category, Finding, ModuleInfo, Output, Severity};
use crate::module::{RunContext, TriageModule};
use serde::{Deserialize, Serialize};
use std::time::Duration;
#[cfg(not(windows))]
use std::time::Instant;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApplicationProbe {
    pub label: String,
    pub url: String,
    pub expected_status: Vec<u16>,
    pub timeout_ms: u64,
    pub slow_ms: u64,
}
impl Default for ApplicationProbe {
    fn default() -> Self {
        Self {
            label: String::new(),
            url: String::new(),
            expected_status: vec![200],
            timeout_ms: 8000,
            slow_ms: 2000,
        }
    }
}

pub fn checked_url(text: &str) -> Result<Url, String> {
    if text.len() > 2048 || text.chars().any(char::is_control) {
        return Err("The application URL is too long or contains control characters.".into());
    }
    let url = Url::parse(text).map_err(|e| format!("Invalid application URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("Use an absolute http:// or https:// URL without credentials or a fragment.".into());
    }
    Ok(url)
}

/// Query parameters can contain secrets. They reach the HTTP client but
/// never appear in the report's address or native error text.
pub fn display_url(url: &Url) -> String {
    let mut shown = url.clone();
    shown.set_query(None);
    shown.to_string()
}

pub struct ApplicationConnections;
impl TriageModule for ApplicationConnections {
    fn info(&self) -> ModuleInfo {
        ModuleInfo::new(
            "net.applications",
            "Application connections",
            Category::Network,
            "Profile-defined application URLs: DNS, direct route, TCP, proxy context, validated TLS and expected HTTP status.",
        )
    }
    fn execute(&self, ctx: &RunContext) -> Result<Output, String> {
        let configured = &ctx.profile().require.application;
        if configured.is_empty() {
            return Ok(Output::new(
                "No application URLs configured",
                vec![Finding::info(
                    "Site profile",
                    "Add [[require.application]] with label, url and expected_status.",
                )],
            ));
        }
        if configured.len() > 16 {
            return Err("At most 16 application URLs per run; split larger profiles.".into());
        }
        let mut findings = Vec::new();
        for app in configured {
            if ctx.cancelled() {
                break;
            }
            if app.expected_status.is_empty() || app.expected_status.iter().any(|s| !(100..=599).contains(s)) {
                findings.push(Finding::warn(
                    &app.label,
                    "Invalid expected_status: use one or more HTTP status codes.",
                ));
                continue;
            }
            let url = match checked_url(&app.url) {
                Ok(u) => u,
                Err(e) => {
                    findings.push(Finding::warn(&app.label, e));
                    continue;
                }
            };
            let label = if app.label.trim().is_empty() {
                display_url(&url)
            } else {
                app.label.chars().take(150).collect()
            };
            ctx.log(format!("Testing {label}: {}", display_url(&url)));
            let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string();
            let timeout = Duration::from_millis(app.timeout_ms.clamp(500, 15_000));
            let resolved = crate::util::within(Duration::from_secs(3), move || crate::net::resolve(&host));
            match resolved {
                Some(Ok(r)) => {
                    findings.push(
                        Finding::ok(format!("{label} · DNS"), format!("{} address(es)", r.addresses.len())).with_metric(
                            r.elapsed.as_secs_f64() * 1000.0,
                            "ms",
                            true,
                        ),
                    );
                    if let Some(ip) = r.addresses.first() {
                        if let Ok(route) = crate::net::route_to(*ip) {
                            findings.push(Finding::info(format!("{label} · direct route"), route.describe()));
                        }
                    }
                    let check = crate::net::tcp_check(&r.addresses, url.port_or_known_default().unwrap_or(443), Duration::from_millis(750));
                    findings.push(match check.connected() {
                        Some((ip, d)) => Finding::ok(format!("{label} · direct TCP"), format!("{ip} answers")).with_metric(
                            d.as_secs_f64() * 1000.0,
                            "ms",
                            true,
                        ),
                        None => Finding::info(format!("{label} · direct TCP"), check.error())
                            .with_detail("This tests the direct route. A proxy can still make the HTTP request succeed."),
                    });
                }
                _ => findings.push(Finding::info(
                    format!("{label} · local DNS"),
                    "No answer within the lookup budget; the proxy's resolver may still work.",
                )),
            }
            match http_probe(&url, timeout) {
                Ok(r) => {
                    let accepted = app.expected_status.contains(&r.status);
                    let severity = if !accepted || r.first_byte_ms > app.slow_ms as f64 { Severity::Warning } else { Severity::Ok };
                    findings.push(Finding::new(format!("{label} · HTTP"), format!("HTTP {} · first response {:.0} ms", r.status, r.first_byte_ms), severity)
                        .with_detail(format!("Expected {:?}. {} Redirects are reported without following them. A 401/403 is an authentication response, not an unreachable server.", app.expected_status, r.client))
                        .with_metric(r.first_byte_ms, "ms", true));
                    if url.scheme() == "https" {
                        findings.push(Finding::ok(format!("{label} · TLS"), "Certificate chain and host name accepted by the HTTP client"));
                    }
                }
                Err(e) => findings.push(Finding::crit(format!("{label} · application request"), e)
                    .with_detail("No credentials are supplied. See Proxy settings for the signed-in user's configuration; this request uses the account running ITriage.")),
            }
        }
        #[cfg(windows)]
        {
            let signed = crate::win::session::console_user();
            let sid = signed.as_deref().and_then(crate::win::session::sid_of);
            let proxy = crate::win::proxy::user(sid.as_deref());
            findings.push(Finding::info("User proxy/PAC", format!("static proxy: {}; PAC: {}; auto-detect: {}", proxy.server.as_deref().unwrap_or("none"), proxy.pac.as_deref().unwrap_or("none"), proxy.auto_detect))
                .with_detail("WinHTTP uses automatic proxy discovery for its own account. When elevated as a different technician, re-run without elevation as the affected user to test that user's proxy path. Browser sign-in is not simulated."));
        }
        let n = findings.iter().filter(|f| f.severity.rank() >= 2).count();
        Ok(Output::new(
            format!("{} application(s) · {n} finding(s) need attention", configured.len()),
            findings,
        ))
    }
}

pub struct HttpProbe {
    pub status: u16,
    pub first_byte_ms: f64,
    pub client: &'static str,
}

#[cfg(windows)]
pub fn http_probe(url: &Url, timeout: Duration) -> Result<HttpProbe, String> {
    crate::win::net::application_probe(url, timeout)
}

#[cfg(not(windows))]
pub fn http_probe(url: &Url, timeout: Duration) -> Result<HttpProbe, String> {
    use crate::util::{capture_for, cmd, command_exists};
    if !command_exists("curl") {
        return Err("curl is required for application HTTP/TLS checks on Linux.".into());
    }
    let mut c = cmd("curl");
    c.args([
        "--disable",
        "--silent",
        "--show-error",
        "--globoff",
        "--proto",
        "=http,https",
        "--max-redirs",
        "0",
        "--max-time",
        &format!("{:.2}", timeout.as_secs_f64()),
        "--max-filesize",
        "65536",
        "--output",
        "/dev/null",
        "--write-out",
        "ITRIAGE-HTTP %{http_code} %{time_starttransfer}\n",
        "--url",
        url.as_str(),
    ]);
    let start = Instant::now();
    let out = capture_for(c, timeout + Duration::from_secs(2))?;
    let row = out.stdout.lines().find_map(|l| l.strip_prefix("ITRIAGE-HTTP ")).unwrap_or_default();
    let mut parts = row.split_whitespace();
    let status = parts.next().and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let ms = parts
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|n| n.is_finite() && *n >= 0.0)
        .map(|n| n * 1000.0)
        .unwrap_or(start.elapsed().as_secs_f64() * 1000.0);
    // curl 63 stops a large response body after the headers have proved
    // connectivity. Don't misreport that deliberate size limit as TLS failure.
    if status > 0 && (out.success() || out.code == Some(63)) {
        return Ok(HttpProbe {
            status,
            first_byte_ms: ms,
            client: "curl uses the proxy environment of the running account.",
        });
    }
    Err(match out.code {
        Some(5) => "The configured proxy name could not be resolved.",
        Some(6) => "The HTTP client's DNS lookup failed.",
        Some(7) => "TCP connection to the server or proxy failed.",
        Some(28) => "The HTTP request timed out.",
        Some(35) => "TLS negotiation failed.",
        Some(60 | 51) => "TLS certificate validation failed (host name, expiry or trust chain).",
        Some(58) => "A client certificate could not be used.",
        _ => "The HTTP client could not complete the request.",
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_health_urls_without_embedded_credentials_are_accepted() {
        for s in [
            "file:///etc/passwd",
            "ftp://host/x",
            "https://u:p@host/x",
            "https://host/#x",
            "https://host/\n",
        ] {
            assert!(checked_url(s).is_err(), "{s}");
        }
        let u = checked_url("https://app.example:8443/health?secret=hidden").unwrap();
        assert_eq!(display_url(&u), "https://app.example:8443/health");
    }
    #[test]
    fn real_http_status_is_preserved_even_when_it_is_not_success() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let until = std::time::Instant::now() + Duration::from_secs(8);
            let mut s = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && std::time::Instant::now() < until => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("fixture server: {e}"),
                }
            };
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut b = [0; 4096];
            let n = s.read(&mut b).unwrap();
            assert!(!String::from_utf8_lossy(&b[..n]).to_lowercase().contains("authorization:"));
            s.write_all(
                b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"fixture\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        });
        let answer = http_probe(&checked_url(&format!("http://{address}/health")).unwrap(), Duration::from_secs(2)).unwrap();
        server.join().unwrap();
        assert_eq!(answer.status, 401);
    }
}
