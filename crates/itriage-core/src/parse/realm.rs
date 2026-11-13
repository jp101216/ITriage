//! Linux domain join: `realm list`, `sssctl domain-status`, `klist -k -t -e`
//! and `adcli testjoin`, and the rows built from them.
//!
//! The `sssctl`, `klist` and `adcli` formats are captured from SSSD 2.9,
//! MIT Kerberos and adcli on Ubuntu 24.04 (a CI runner with SSSD pointed at
//! an unreachable domain controller). `realm list` printed nothing there, as
//! it does on any PC realmd didn't join, so its parser follows realmd's
//! documented `key: value` layout under each realm's name.

use crate::model::{Finding, Severity};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Realm {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

impl Realm {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// `realm list`: an unindented realm name, then indented `key: value` lines.
pub fn realm_list(text: &str) -> Vec<Realm> {
    let mut out: Vec<Realm> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            out.push(Realm { name: line.trim().to_string(), fields: Vec::new() });
        } else if let (Some(realm), Some((k, v))) = (out.last_mut(), line.trim().split_once(':')) {
            realm.fields.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DomainStatus {
    pub online: Option<bool>,
    /// "AD Domain Controller" → "dc01.corp.example.org" or "not connected".
    pub active: Vec<(String, String)>,
    pub discovered: usize,
}

/// `sssctl domain-status <domain>`.
pub fn domain_status(text: &str) -> DomainStatus {
    let mut status = DomainStatus::default();
    let mut section = "";
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(v) = line.strip_prefix("Online status:") {
            status.online = match v.trim() {
                "Online" => Some(true),
                "Offline" => Some(false),
                _ => None,
            };
        } else if line == "Active servers:" {
            section = "active";
        } else if line.starts_with("Discovered ") && line.ends_with(':') {
            section = "discovered";
        } else if section == "active" {
            if let Some((k, v)) = line.split_once(": ") {
                status.active.push((k.to_string(), v.to_string()));
            }
        } else if section == "discovered" && line.starts_with("- ") {
            status.discovered += 1;
        }
    }
    status
}

/// The `domains =` line of `sssd.conf`'s `[sssd]` section: what SSSD is set
/// up for even when it won't start.
pub fn conf_domains(text: &str) -> Vec<String> {
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']).trim().to_ascii_lowercase();
        } else if section == "sssd" {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "domains" {
                    return v.split(',').map(str::trim).filter(|d| !d.is_empty()).map(str::to_string).collect();
                }
            }
        }
    }
    Vec::new()
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeytabEntry {
    pub kvno: u32,
    pub principal: String,
    pub enctype: String,
}

/// `klist -k -t -e`: `KVNO Timestamp Principal (enctype)`.
pub fn keytab(text: &str) -> Vec<KeytabEntry> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let kvno: u32 = parts.next()?.parse().ok()?;
            let rest: Vec<&str> = parts.collect();
            // Date and time come before the principal; the enctype is last,
            // in parentheses.
            let enctype = rest.last().filter(|e| e.starts_with('(')).map(|e| e.trim_matches(['(', ')']).to_string()).unwrap_or_default();
            let principal = rest.iter().find(|p| p.contains('@'))?.to_string();
            Some(KeytabEntry { kvno, principal, enctype })
        })
        .collect()
}

fn weak(enctype: &str) -> bool {
    let e = enctype.to_ascii_lowercase();
    e.starts_with("arcfour") || e.starts_with("rc4") || e.starts_with("des")
}

/// What was read on this PC.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub realms: Vec<Realm>,
    /// SSSD's own domain list (`sssctl domain-list`).
    pub sssd_domains: Vec<String>,
    /// Per domain: the status, or why it couldn't be read.
    pub status: Vec<(String, Result<DomainStatus, String>)>,
    /// `adcli testjoin`: Ok(output) or Err(output); `None` when not run.
    pub testjoin: Option<Result<String, String>>,
    pub keytab: Option<Result<Vec<KeytabEntry>, String>>,
    /// `/etc/sssd/sssd.conf`: permission bits and owner, when it exists.
    pub conf: Option<(u32, u32)>,
    pub root: bool,
}

pub fn findings(f: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    let joined = !f.realms.is_empty() || !f.sssd_domains.is_empty();
    if !joined && f.conf.is_none() {
        out.push(Finding::info("Domain", "not joined (realm list and SSSD name no domain)"));
        return out;
    }
    for r in &f.realms {
        let words = [r.get("client-software"), r.get("configured")].into_iter().flatten().collect::<Vec<_>>().join(", ");
        let mut detail = Vec::new();
        for key in ["server-software", "login-formats", "login-policy"] {
            if let Some(v) = r.get(key) {
                detail.push(format!("{key}: {v}"));
            }
        }
        let row = match r.get("configured") {
            Some("no") => Finding::warn(format!("Realm {}", r.name), "discovered but not joined"),
            _ => Finding::ok(format!("Realm {}", r.name), if words.is_empty() { "joined".to_string() } else { words }),
        };
        out.push(if detail.is_empty() { row } else { row.with_detail(detail.join(" · ")) });
    }
    if f.realms.is_empty() && !f.sssd_domains.is_empty() {
        out.push(Finding::info("Realm", format!("realmd lists none; SSSD is set up for {}", f.sssd_domains.join(", "))));
    }
    if let Some((mode, uid)) = f.conf {
        let perms = mode & 0o777;
        out.push(if perms & 0o077 != 0 || uid != 0 {
            Finding::crit("SSSD configuration", format!("/etc/sssd/sssd.conf is {perms:04o}, owned by uid {uid}"))
                .with_detail("SSSD refuses to start unless sssd.conf is owned by root and readable by nobody else: chmod 600 and chown root:root, then restart sssd.")
        } else {
            Finding::ok("SSSD configuration", format!("/etc/sssd/sssd.conf is {perms:04o}, owned by root"))
        });
    }
    for (domain, status) in &f.status {
        out.push(match status {
            Err(e) => Finding::info(format!("Domain {domain}"), format!("status not available: {e}")),
            Ok(s) => {
                let servers = s.active.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(" · ");
                match s.online {
                    Some(true) => Finding::ok(format!("Domain {domain}"), "online").with_detail(servers),
                    Some(false) => Finding::warn(format!("Domain {domain}"), "offline: sign-ins use cached credentials")
                        .with_detail(format!("SSSD can't reach a domain controller{}. People who have signed in here before can still sign in with their cached password; anyone new can't, and password changes fail. {servers}", if s.discovered > 0 { format!(" ({} discovered)", s.discovered) } else { String::new() })),
                    None => Finding::info(format!("Domain {domain}"), "status unknown").with_detail(servers),
                }
            }
        });
    }
    match &f.testjoin {
        None if !f.root => out.push(Finding::info("Machine account", "not checked: adcli testjoin needs root")),
        None => {}
        Some(Ok(text)) => out.push(Finding::ok("Machine account", "valid (adcli testjoin)").with_detail(text.trim().to_string())),
        Some(Err(text)) => {
            let message = text.trim().trim_start_matches("adcli: ").to_string();
            let unreachable = message.contains("usable domain controller") || message.contains("couldn't connect");
            out.push(if unreachable {
                Finding::warn("Machine account", "not tested: no domain controller answered").with_detail(message)
            } else {
                Finding::crit("Machine account", "adcli testjoin failed").with_detail(format!(
                    "{message}. The computer account's password on the domain no longer matches this PC's keytab (reset, or the PC was re-imaged): rejoin with realm leave and realm join."
                ))
            });
        }
    }
    match &f.keytab {
        None if !f.root => out.push(Finding::info("Machine keytab", "not read: /etc/krb5.keytab needs root")),
        None => {}
        Some(Err(e)) => out.push(Finding::warn("Machine keytab", e.clone())),
        Some(Ok(entries)) if entries.is_empty() => out.push(Finding::warn("Machine keytab", "/etc/krb5.keytab has no keys")),
        Some(Ok(entries)) => {
            let newest = entries.iter().map(|e| e.kvno).max().unwrap_or(0);
            let mut principals: Vec<&str> = entries.iter().filter(|e| e.kvno == newest).map(|e| e.principal.as_str()).collect();
            principals.sort_unstable();
            principals.dedup();
            let all_weak = entries.iter().filter(|e| e.kvno == newest).all(|e| !e.enctype.is_empty() && weak(&e.enctype));
            let row = Finding::new(
                "Machine keytab",
                format!("{} key{} · KVNO {newest}", entries.len(), if entries.len() == 1 { "" } else { "s" }),
                if all_weak { Severity::Warning } else { Severity::Ok },
            );
            out.push(row.with_detail(format!(
                "{}{}",
                principals.join(", "),
                if all_weak { ". Only RC4 or DES keys: domain controllers are dropping RC4, so rejoin to get AES keys." } else { "" }
            )));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "corp.example.org
  type: kerberos
  realm-name: CORP.EXAMPLE.ORG
  domain-name: corp.example.org
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: adcli
  login-formats: %U@corp.example.org
  login-policy: allow-realm-logins
";

    #[test]
    fn reads_realms_status_and_keytabs() {
        let realms = realm_list(REALM);
        assert_eq!(realms.len(), 1);
        assert_eq!((realms[0].name.as_str(), realms[0].get("client-software"), realms[0].get("login-formats")), ("corp.example.org", Some("sssd"), Some("%U@corp.example.org")));
        assert!(realm_list("").is_empty());

        let conf = "[sssd]\ndomains = corp.example.org, lab.example.org\nservices = nss, pam\n\n[domain/corp.example.org]\ndomains = not.this\n";
        assert_eq!(conf_domains(conf), vec!["corp.example.org".to_string(), "lab.example.org".to_string()]);
        assert!(conf_domains("[domain/x]\ndomains = y\n").is_empty());

        let offline = domain_status(include_str!("fixtures/sssctl-domain-status-offline.txt"));
        assert_eq!(offline.online, Some(false));
        assert_eq!(offline.active, vec![("AD Global Catalog".into(), "not connected".into()), ("AD Domain Controller".into(), "192.0.2.10".into())]);
        assert_eq!(offline.discovered, 2);
        assert_eq!(domain_status("Online status: Online\n\nActive servers:\nAD Domain Controller: dc01.corp.example.org\n").online, Some(true));

        let keys = keytab(include_str!("fixtures/klist-keytab.txt"));
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], KeytabEntry { kvno: 3, principal: "WS-07$@CORP.EXAMPLE.ORG".into(), enctype: "aes256-cts-hmac-sha1-96".into() });
        assert_eq!(keys[2].kvno, 2);
    }

    #[test]
    fn grades_a_joined_pc() {
        let f = Facts {
            realms: realm_list(REALM),
            sssd_domains: vec!["corp.example.org".into()],
            status: vec![("corp.example.org".into(), Ok(domain_status(include_str!("fixtures/sssctl-domain-status-offline.txt"))))],
            testjoin: Some(Err("adcli: couldn't connect to corp.example.org domain: Couldn't find usable domain controller to connect to".into())),
            keytab: Some(Ok(keytab(include_str!("fixtures/klist-keytab.txt")))),
            conf: Some((0o100644, 0)),
            root: true,
        };
        let rows = findings(&f);
        let row = |label: &str| rows.iter().find(|r| r.label == label).unwrap();
        assert_eq!(row("Realm corp.example.org").value, "sssd, kerberos-member");
        assert_eq!(row("SSSD configuration").severity, Severity::Critical);
        assert_eq!(row("SSSD configuration").value, "/etc/sssd/sssd.conf is 0644, owned by uid 0");
        assert_eq!(row("Domain corp.example.org").severity, Severity::Warning);
        assert_eq!(row("Machine account").severity, Severity::Warning, "no DC isn't a broken account");
        assert_eq!(row("Machine keytab").value, "3 keys · KVNO 3");
        assert_eq!(row("Machine keytab").detail.as_deref(), Some("WS-07$@CORP.EXAMPLE.ORG, host/ws-07.corp.example.org@CORP.EXAMPLE.ORG"));

        let broken = findings(&Facts { testjoin: Some(Err("adcli: Couldn't authenticate as machine account: WS-07$: Preauthentication failed".into())), conf: Some((0o100600, 0)), ..f.clone() });
        assert_eq!(broken.iter().find(|r| r.label == "Machine account").unwrap().severity, Severity::Critical);
        assert_eq!(broken.iter().find(|r| r.label == "SSSD configuration").unwrap().severity, Severity::Ok);
    }

    #[test]
    fn an_unjoined_pc_and_a_non_root_run() {
        assert_eq!(findings(&Facts::default())[0].value, "not joined (realm list and SSSD name no domain)");
        let user = findings(&Facts { sssd_domains: vec!["corp.example.org".into()], status: vec![("corp.example.org".into(), Err("'domain-status' must be run as root".into()))], ..Facts::default() });
        assert!(user.iter().any(|r| r.value == "not checked: adcli testjoin needs root"));
        assert!(user.iter().any(|r| r.value == "not read: /etc/krb5.keytab needs root"));
        let rc4 = vec![KeytabEntry { kvno: 2, principal: "WS-07$@CORP.EXAMPLE.ORG".into(), enctype: "arcfour-hmac".into() }];
        let weak = findings(&Facts { sssd_domains: vec!["corp.example.org".into()], keytab: Some(Ok(rc4)), root: true, ..Facts::default() });
        assert_eq!(weak.iter().find(|r| r.label == "Machine keytab").unwrap().severity, Severity::Warning);
    }
}
