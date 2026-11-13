//! Kerberos tickets cached for a sign-in, and what's wrong with them.
//!
//! Windows lists them through LSA (`KerbQueryTicketCacheEx3Message`, what
//! `klist` uses); Linux through MIT `klist -e`. Either way the grading is
//! the same: is there a ticket-granting ticket and is it current, which
//! services still hand out RC4 (or DES) tickets, and which server rejected
//! a ticket outright (System event 4, KRB_AP_ERR_MODIFIED). Field names for
//! event 4 are from the Security-Kerberos manifest: `Server`, `TargetRealm`,
//! `Targetname`, `ClientRealm`.

use crate::model::{Finding, Severity};
use crate::parse::blocks::field;
use crate::parse::evtxml::{parse_system, payload};
use crate::parse::time::{epoch_to_rfc3339, iso8601_utc_to_epoch};
use crate::util::{ago, plural};

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    pub client: String,
    /// The service principal: `krbtgt/CORP.EXAMPLE.ORG`, `cifs/fs01.corp.example.org`.
    pub server: String,
    pub realm: String,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub renew: Option<u64>,
    /// The ticket's encryption type (RFC 3961 numbers: 18 is AES-256, 23 RC4).
    pub etype: Option<i32>,
    /// The domain controller it came from, when Windows says.
    pub kdc: String,
}

impl Ticket {
    pub fn is_tgt(&self) -> bool {
        self.server.to_ascii_lowercase().starts_with("krbtgt/")
    }
}

/// An encryption type's name, as `klist` prints it.
pub fn etype_name(etype: i32) -> String {
    match etype {
        1 => "DES-CBC-CRC".into(),
        3 => "DES-CBC-MD5".into(),
        17 => "AES-128".into(),
        18 => "AES-256".into(),
        19 => "AES-128 (SHA-256)".into(),
        20 => "AES-256 (SHA-384)".into(),
        23 => "RC4-HMAC".into(),
        24 => "RC4-HMAC (export)".into(),
        n => format!("type {n}"),
    }
}

/// The encryption type behind an MIT name: `aes256-cts-hmac-sha1-96` → 18.
fn mit_etype(name: &str) -> Option<i32> {
    let n = name.trim().trim_start_matches("DEPRECATED:").to_ascii_lowercase();
    Some(match n.as_str() {
        "des-cbc-crc" => 1,
        "des-cbc-md5" => 3,
        "aes128-cts-hmac-sha1-96" | "aes128-cts" => 17,
        "aes256-cts-hmac-sha1-96" | "aes256-cts" => 18,
        "aes128-cts-hmac-sha256-128" => 19,
        "aes256-cts-hmac-sha384-192" => 20,
        "arcfour-hmac" | "rc4-hmac" | "arcfour-hmac-md5" => 23,
        "arcfour-hmac-exp" | "rc4-hmac-exp" => 24,
        _ => return None,
    })
}

fn weak(etype: Option<i32>) -> Option<Severity> {
    match etype? {
        1 | 3 => Some(Severity::Critical),
        23 | 24 => Some(Severity::Warning),
        _ => None,
    }
}

/// `11/12/26 08:01:13` or `11/12/2026 08:01:13` (MIT klist in the C
/// locale, local time) as Unix seconds, with the local offset applied by
/// `local_to_utc`.
fn mit_time(date: &str, clock: &str, local_to_utc: &dyn Fn(u64) -> u64) -> Option<u64> {
    let mut d = date.split('/');
    let (m, day, y) = (d.next()?, d.next()?, d.next()?);
    let year = match y.len() {
        2 => format!("20{y}"),
        4 => y.to_string(),
        _ => return None,
    };
    let iso = format!("{year}-{m:0>2}-{day:0>2}T{clock}Z");
    iso8601_utc_to_epoch(&iso).map(local_to_utc)
}

/// The output of MIT `klist -e` (run with `LC_ALL=C`): the default
/// principal and each ticket. Times are local, turned into UTC by
/// `local_to_utc`.
pub fn klist_mit(text: &str, local_to_utc: &dyn Fn(u64) -> u64) -> (Option<String>, Vec<Ticket>) {
    let mut principal = None;
    let mut tickets: Vec<Ticket> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(p) = trimmed.strip_prefix("Default principal:") {
            principal = Some(p.trim().to_string());
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        // "11/12/26 08:01:13  11/12/26 18:01:13  krbtgt/CORP.EXAMPLE.ORG@CORP.EXAMPLE.ORG"
        if parts.len() >= 5 && parts[0].matches('/').count() == 2 && parts[1].contains(':') {
            let service = parts[4];
            let (server, realm) = service.rsplit_once('@').unwrap_or((service, ""));
            tickets.push(Ticket {
                client: principal.clone().unwrap_or_default(),
                server: server.to_string(),
                realm: realm.to_string(),
                start: mit_time(parts[0], parts[1], local_to_utc),
                end: mit_time(parts[2], parts[3], local_to_utc),
                renew: None,
                etype: None,
                kdc: String::new(),
            });
            continue;
        }
        let Some(last) = tickets.last_mut() else { continue };
        // "renew until 11/19/26 08:01:11, Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96"
        for part in trimmed.split(", Etype") {
            if let Some(rest) = part.trim().strip_prefix("renew until ") {
                let mut w = rest.split_whitespace();
                if let (Some(d), Some(c)) = (w.next(), w.next()) {
                    last.renew = mit_time(d, c.trim_end_matches(','), local_to_utc);
                }
            }
        }
        if let Some((_, types)) = trimmed.split_once("(skey, tkt):") {
            // The ticket's own encryption is the second one.
            let mut names = types.split(',').map(str::trim);
            let skey = names.next().and_then(mit_etype);
            last.etype = names.next().and_then(mit_etype).or(skey);
        }
    }
    (principal, tickets)
}

/// A System event 4 (KRB_AP_ERR_MODIFIED): when, the server, the target.
pub fn modified_error(xml: &str) -> Option<(u64, String, String)> {
    let system = parse_system(xml)?;
    if system.event_id != 4 || !system.provider.to_ascii_lowercase().contains("kerberos") {
        return None;
    }
    let data = payload(xml);
    let server = field(&data, &["Server"]).unwrap_or_default().to_string();
    let target = field(&data, &["Targetname"]).unwrap_or_default().to_string();
    Some((iso8601_utc_to_epoch(system.time_created.as_deref()?)?, server, target))
}

fn until(now: u64, end: u64) -> String {
    if end > now {
        let left = end - now;
        let words = if left >= 3_600 { format!("{}h", left / 3_600) } else { format!("{}m", left / 60) };
        format!("valid until {} UTC (another {words})", &epoch_to_rfc3339(end)[11..16])
    } else {
        format!("expired {}", ago(now - end))
    }
}

/// What the cached tickets say. `purge` is the fix to offer, when it can
/// run in this context.
pub fn findings(tickets: &[Ticket], now: u64, purge: Option<crate::model::FixRef>) -> Vec<Finding> {
    let with_purge = |f: Finding| match &purge {
        Some(a) => f.with_action(a.clone()),
        None => f,
    };
    if tickets.is_empty() {
        return vec![Finding::info("Kerberos tickets", "none cached for this sign-in").with_detail(
            "Normal for a local or Microsoft Entra-only account. On a domain account it means nothing has needed one yet, or they were just cleared.",
        )];
    }
    let mut out = Vec::new();
    let services: Vec<&Ticket> = tickets.iter().filter(|t| !t.is_tgt()).collect();
    match tickets.iter().find(|t| t.is_tgt()) {
        Some(tgt) => {
            let expired = tgt.end.is_some_and(|e| e <= now);
            let value = match tgt.end {
                Some(end) => until(now, end),
                None => "present".to_string(),
            };
            let f = Finding::new("Kerberos TGT", value, if expired { Severity::Warning } else { Severity::Ok })
                .with_detail(format!("{} for {}{}", tgt.server, tgt.client, tgt.renew.map(|r| format!(" · renewable until {} UTC", epoch_to_rfc3339(r))).unwrap_or_default()));
            out.push(if expired { with_purge(f) } else { f });
        }
        None => out.push(with_purge(
            Finding::warn("Kerberos TGT", "none: new service tickets can't be issued").with_detail("The sign-in has service tickets but no ticket-granting ticket. Locking and unlocking the PC (or clearing the tickets) gets a new one."),
        )),
    }
    let mut names: Vec<&str> = services.iter().map(|t| t.server.as_str()).collect();
    names.sort();
    names.dedup();
    out.push(
        Finding::info("Kerberos service tickets", format!("{} cached", services.len()))
            .with_detail(names.iter().take(6).copied().collect::<Vec<_>>().join(", ")),
    );
    for (severity, what) in [(Severity::Critical, "DES"), (Severity::Warning, "RC4")] {
        let hits: Vec<&Ticket> = tickets.iter().filter(|t| weak(t.etype) == Some(severity)).collect();
        if hits.is_empty() {
            continue;
        }
        let mut servers: Vec<&str> = hits.iter().map(|t| t.server.as_str()).collect();
        servers.dedup();
        out.push(
            Finding::new(format!("Kerberos {what} tickets"), format!("{} ticket{}: {}", hits.len(), plural(hits.len()), servers.iter().take(4).copied().collect::<Vec<_>>().join(", ")), severity).with_detail(
                if what == "RC4" {
                    "Microsoft is removing RC4 from Kerberos on domain controllers; these services (or their accounts) still only offer it, and will stop working when it goes. Their owners need AES enabled on the service account (msDS-SupportedEncryptionTypes)."
                } else {
                    "DES is broken and disabled by default since Windows 7. A service that still uses it needs its account fixed now."
                },
            ),
        );
    }
    if let Some(kdc) = tickets.iter().map(|t| t.kdc.trim_start_matches('\\')).find(|k| !k.is_empty()) {
        out.push(Finding::info("Kerberos KDC", kdc.to_string()));
    }
    out
}

/// One row per server that rejected a ticket in the window.
pub fn rejections(events: &[(u64, String, String)], now: u64, purge: Option<crate::model::FixRef>) -> Vec<Finding> {
    let mut servers: Vec<&str> = events.iter().map(|(_, s, _)| s.as_str()).collect();
    servers.sort();
    servers.dedup();
    servers
        .into_iter()
        .map(|server| {
            let hits: Vec<&(u64, String, String)> = events.iter().filter(|(_, s, _)| s == server).collect();
            let last = hits.iter().map(|(t, _, _)| *t).max().unwrap_or(now);
            let target = hits.iter().map(|(_, _, t)| t.as_str()).find(|t| !t.is_empty()).unwrap_or("its service name");
            let name = if server.is_empty() { "a server" } else { server };
            let f = Finding::crit(
                format!("Kerberos ticket rejected by {name}"),
                format!("KRB_AP_ERR_MODIFIED {} in 7 days · last {}", match hits.len() { 1 => "once".to_string(), 2 => "twice".to_string(), n => format!("{n} times") }, ago(now.saturating_sub(last))),
            )
            .with_detail(format!(
                "Target name {target}. The server couldn't decrypt its ticket: the name is registered on another account too (a duplicate SPN), or the server's account password no longer matches the domain's. Check with setspn -Q {target}; once it's fixed, clear the cached tickets."
            ));
            match &purge {
                Some(a) => f.with_action(a.clone()),
                None => f,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_794_496_800; // 2026-11-12T15:20:00Z

    fn ticket(server: &str, etype: i32, end: u64) -> Ticket {
        Ticket {
            client: "jparker@CORP.EXAMPLE.ORG".into(),
            server: server.into(),
            realm: "CORP.EXAMPLE.ORG".into(),
            start: Some(end - 36_000),
            end: Some(end),
            renew: None,
            etype: Some(etype),
            kdc: "\\\\DC01.corp.example.org".into(),
        }
    }

    #[test]
    fn grades_the_tgt_rc4_and_the_kdc() {
        let rows = findings(
            &[ticket("krbtgt/CORP.EXAMPLE.ORG", 18, NOW + 25_200), ticket("cifs/fs01.corp.example.org", 18, NOW + 25_200), ticket("MSSQLSvc/oldsql.corp.example.org:1433", 23, NOW + 25_200)],
            NOW,
            None,
        );
        let get = |l: &str| rows.iter().find(|f| f.label == l).unwrap_or_else(|| panic!("{l}: {rows:#?}"));
        assert_eq!(get("Kerberos TGT").severity, Severity::Ok);
        assert_eq!(get("Kerberos TGT").value, "valid until 22:20 UTC (another 7h)");
        assert_eq!(get("Kerberos service tickets").value, "2 cached");
        let rc4 = get("Kerberos RC4 tickets");
        assert_eq!((rc4.severity, rc4.value.as_str()), (Severity::Warning, "1 ticket: MSSQLSvc/oldsql.corp.example.org:1433"));
        assert_eq!(get("Kerberos KDC").value, "DC01.corp.example.org");
    }

    #[test]
    fn a_missing_or_expired_tgt_offers_the_purge() {
        let purge = Some(crate::actions::offer("purge-kerberos-tickets", None));
        let expired = findings(&[ticket("krbtgt/CORP.EXAMPLE.ORG", 18, NOW - 600)], NOW, purge.clone());
        assert_eq!((expired[0].severity, expired[0].value.as_str()), (Severity::Warning, "expired 10m ago"));
        assert!(expired[0].action.is_some());
        let missing = findings(&[ticket("cifs/fs01", 18, NOW + 60)], NOW, purge);
        assert!(missing[0].value.starts_with("none") && missing[0].action.is_some());
        assert_eq!(findings(&[], NOW, None)[0].severity, Severity::Info);
        let des = findings(&[ticket("krbtgt/X", 18, NOW + 60), ticket("host/legacy", 3, NOW + 60)], NOW, None);
        assert!(des.iter().any(|f| f.label == "Kerberos DES tickets" && f.severity == Severity::Critical));
    }

    #[test]
    fn reads_mit_klist() {
        let text = "Ticket cache: FILE:/tmp/krb5cc_1000\nDefault principal: jparker@CORP.EXAMPLE.ORG\n\n\
            Valid starting       Expires              Service principal\n\
            11/12/26 08:01:13  11/12/26 18:01:13  krbtgt/CORP.EXAMPLE.ORG@CORP.EXAMPLE.ORG\n\
            \trenew until 11/19/26 08:01:11, Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 \n\
            11/12/26 08:05:40  11/12/26 18:01:13  cifs/fs01.corp.example.org@CORP.EXAMPLE.ORG\n\
            \tEtype (skey, tkt): aes256-cts-hmac-sha1-96, DEPRECATED:arcfour-hmac \n";
        let (principal, tickets) = klist_mit(text, &|t| t + 5 * 3_600);
        assert_eq!(principal.as_deref(), Some("jparker@CORP.EXAMPLE.ORG"));
        assert_eq!(tickets.len(), 2);
        assert!(tickets[0].is_tgt());
        assert_eq!(tickets[0].end, iso8601_utc_to_epoch("2026-11-12T23:01:13Z"), "local time made UTC");
        assert_eq!(tickets[0].renew, iso8601_utc_to_epoch("2026-11-19T13:01:11Z"));
        assert_eq!((tickets[0].etype, tickets[1].etype), (Some(18), Some(23)), "the ticket's own type, the second one");
        assert_eq!(tickets[1].server, "cifs/fs01.corp.example.org");
        let (none, empty) = klist_mit("klist: No credentials cache found (filename: /tmp/krb5cc_1000)\n", &|t| t);
        assert!(none.is_none() && empty.is_empty());
    }

    #[test]
    fn reads_event_4_and_folds_by_server() {
        let xml = "<Event><System><Provider Name='Microsoft-Windows-Security-Kerberos' Guid='{98e6cfcb-ee0a-41e0-a57b-622d4e1b30b1}' EventSourceName='Kerberos'/>\
            <EventID Qualifiers='16384'>4</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-12T15:00:00.0000000Z'/></System>\
            <EventData><Data Name='Server'>fs01$</Data><Data Name='TargetRealm'>CORP.EXAMPLE.ORG</Data><Data Name='Targetname'>cifs/fs01.corp.example.org</Data><Data Name='ClientRealm'>CORP.EXAMPLE.ORG</Data><Data Name='binary'>1B00</Data></EventData></Event>";
        let e = modified_error(xml).unwrap();
        assert_eq!((e.1.as_str(), e.2.as_str()), ("fs01$", "cifs/fs01.corp.example.org"));
        let rows = rejections(&[e.clone(), (e.0 - 600, e.1.clone(), e.2.clone())], NOW, None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "Kerberos ticket rejected by fs01$");
        assert_eq!(rows[0].value, "KRB_AP_ERR_MODIFIED twice in 7 days · last 20m ago");
        assert!(rows[0].detail.as_deref().unwrap().contains("setspn -Q cifs/fs01.corp.example.org"));
        assert!(modified_error(&xml.replace(">4</EventID>", ">3</EventID>")).is_none());
    }
}
