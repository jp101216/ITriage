//! Proxy settings. Read-only.
//!
//! Windows: the machine-wide WinHTTP proxy (what services and Windows Update
//! use) and the signed-in user's own proxy, PAC script or auto-detect setting
//! from their hive, as Invoke-NetTriage reads them. Linux: proxy environment
//! variables and the desktop's proxy setting. Passwords in proxy URLs are
//! never shown.

use crate::model::{Category, Finding, ModuleInfo, Output};
use crate::module::{RunContext, TriageModule};
use crate::parse::text::redact_userinfo;

pub struct ProxySettings;

impl TriageModule for ProxySettings {
    fn info(&self) -> ModuleInfo {
        let description = if cfg!(windows) {
            "The machine-wide WinHTTP proxy, and the signed-in user's proxy, PAC script or auto-detect setting."
        } else {
            "Proxy environment variables and the desktop's proxy setting."
        };
        ModuleInfo::new("net.proxy", "Proxy settings", Category::Network, description)
    }

    fn execute(&self, _ctx: &RunContext) -> Result<Output, String> {
        let (findings, summary) = imp::read();
        Ok(Output::new(summary, findings))
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::win::{proxy, session};

    pub fn read() -> (Vec<Finding>, String) {
        let mut findings = Vec::new();
        let mut parts = Vec::new();

        match proxy::winhttp() {
            Ok(w) => {
                let value = match &w.proxy {
                    Some(p) => {
                        parts.push(format!("WinHTTP via {}", redact_userinfo(p)));
                        redact_userinfo(p)
                    }
                    None => "Direct (no proxy)".to_string(),
                };
                let mut f = Finding::info("WinHTTP proxy (machine)", value);
                if let Some(b) = w.bypass.filter(|_| w.proxy.is_some()) {
                    f = f.with_detail(format!("Bypass list: {b}"));
                }
                findings.push(f);
            }
            Err(e) => findings.push(Finding::info("WinHTTP proxy (machine)", e)),
        }

        // The person at the console, who may not be the account itriage runs as.
        let me = session::current_account();
        let user = session::console_user().or_else(|| me.clone());
        let sid = match (&user, &me) {
            (Some(u), Some(m)) if !u.eq_ignore_ascii_case(m) => session::sid_of(u),
            _ => None,
        };
        let u = proxy::user(sid.as_deref());
        // NetTriage's order: an enabled proxy server, then a PAC URL.
        let value = if let Some(server) = &u.server {
            parts.push(format!("user via {}", redact_userinfo(server)));
            redact_userinfo(server)
        } else if let Some(pac) = &u.pac {
            parts.push("user via PAC".into());
            format!("PAC: {}", redact_userinfo(pac))
        } else if u.auto_detect {
            parts.push("user auto-detect (WPAD)".into());
            "Automatically detect settings (WPAD)".to_string()
        } else {
            "Direct (no proxy)".to_string()
        };
        let label = match &user {
            Some(name) => format!("User proxy ({name})"),
            None => "User proxy".to_string(),
        };
        let mut f = Finding::info(label, value);
        let mut notes = Vec::new();
        if u.server.is_some() && u.auto_detect {
            notes.push("auto-detect is also on".to_string());
        }
        if let Some(b) = &u.bypass {
            notes.push(format!("bypass: {b}"));
        }
        if sid.is_none() && user != me && user.is_some() {
            notes.push("read from the account ITriage runs as".into());
        }
        f = f.with_detail(notes.join(" · "));
        findings.push(f);

        let summary = if parts.is_empty() { "Direct: no proxy configured".to_string() } else { cap(&parts.join(" · ")) };
        (findings, summary)
    }

    fn cap(s: &str) -> String {
        crate::triage::network::capitalize(s)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::util::{capture, cmd, command_exists};

    fn gsettings(schema: &str, key: &str) -> Option<String> {
        let mut c = cmd("gsettings");
        c.args(["get", schema, key]);
        let out = capture(c).ok().filter(|o| o.success())?;
        let v = out.stdout.trim().trim_matches('\'').to_string();
        (!v.is_empty() && v != "@as []").then_some(v)
    }

    pub fn read() -> (Vec<Finding>, String) {
        let mut findings = Vec::new();
        let mut parts = Vec::new();
        for var in ["https_proxy", "http_proxy", "all_proxy", "no_proxy"] {
            let value = std::env::var(var)
                .ok()
                .or_else(|| std::env::var(var.to_uppercase()).ok())
                .filter(|v| !v.trim().is_empty());
            if let Some(v) = value {
                if var != "no_proxy" {
                    parts.push(format!("proxy set in the environment ({var})"));
                }
                let shown = redact_userinfo(&v);
                let short = crate::parse::text::truncate_chars(&shown, 120);
                let f = Finding::info(format!("Environment ({var})"), short.clone());
                findings.push(if short != shown { f.with_detail(shown) } else { f });
            }
        }
        if command_exists("gsettings") {
            if let Some(mode) = gsettings("org.gnome.system.proxy", "mode") {
                let value = match mode.as_str() {
                    "manual" => {
                        let host = gsettings("org.gnome.system.proxy.http", "host").unwrap_or_default();
                        let port = gsettings("org.gnome.system.proxy.http", "port").unwrap_or_default();
                        parts.push("desktop proxy".into());
                        format!("Manual: {host}:{port}")
                    }
                    "auto" => {
                        parts.push("desktop PAC".into());
                        match gsettings("org.gnome.system.proxy", "autoconfig-url") {
                            Some(url) => format!("PAC: {}", redact_userinfo(&url)),
                            None => "Automatic (WPAD)".into(),
                        }
                    }
                    _ => "Direct (no proxy)".into(),
                };
                findings.push(Finding::info("Desktop proxy (GNOME)", value));
            }
        }
        if findings.is_empty() {
            findings.push(Finding::info("Proxy", "Direct (no proxy configured)"));
        }
        let summary = if parts.is_empty() {
            "Direct: no proxy configured".to_string()
        } else {
            crate::triage::network::capitalize(&parts.join(" · "))
        };
        (findings, summary)
    }
}
