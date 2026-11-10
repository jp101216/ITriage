//! Which files ITriage will act on when it has administrator rights.
//!
//! An elevated ITriage starts other programs (the manufacturer's update tool,
//! Windows' own tools) and obeys a machine-wide profile. If a standard user
//! could replace any of those, they could get their own code run as an
//! administrator, or rewrite the policy the organisation set. So before an
//! elevated run uses a file that isn't part of Windows, it checks that only
//! administrators could have put it there:
//!
//! * the file and its folder are owned by Administrators, SYSTEM or
//!   TrustedInstaller, and nobody else may write to them;
//! * nobody else may rename or replace any folder above them.
//!
//! `C:\Program Files\…` passes. A folder a user made at the top of `C:\`
//! doesn't, even if an administrator later put files in it: Windows lets
//! every signed-in user write to folders created there.
//!
//! On Linux the same question is "owned by root, and not writable by group
//! or others".

use std::path::Path;

/// One entry of a Windows access list, reduced to what matters here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// An "allow" entry (deny entries only ever take rights away).
    pub allow: bool,
    /// Applies to children only, not to the object it's on.
    pub inherit_only: bool,
    pub mask: u32,
    /// The account, as a SID string (`S-1-5-32-545`).
    pub sid: String,
}

/// What the object is to the file being checked; the rights that matter differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The file itself: nobody else may change or replace it.
    File,
    /// The folder it's in: nobody else may add, change or remove anything
    /// (a planted DLL beside a program is loaded by it).
    Folder,
    /// A folder further up: nobody else may rename or remove what's inside.
    Ancestor,
    /// The drive's root: as an ancestor, but users creating new top-level
    /// folders there is normal.
    Root,
}

const FILE_WRITE_DATA: u32 = 0x2; // on a folder: add a file
const FILE_APPEND_DATA: u32 = 0x4; // on a folder: add a subfolder
const FILE_DELETE_CHILD: u32 = 0x40;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

const TAKEOVER: u32 = WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;

impl Kind {
    /// The rights that would let someone tamper with this object.
    fn dangerous(self) -> u32 {
        match self {
            Kind::File => TAKEOVER | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE,
            Kind::Folder => TAKEOVER | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE,
            Kind::Ancestor => TAKEOVER | FILE_DELETE_CHILD | DELETE,
            Kind::Root => TAKEOVER | FILE_DELETE_CHILD,
        }
    }
}

/// Administrators, SYSTEM and TrustedInstaller: the accounts that already
/// have administrator rights.
const TRUSTED: [&str; 3] = [
    "S-1-5-32-544",
    "S-1-5-18",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// CREATOR OWNER and CREATOR GROUP are placeholders that only describe what
/// a child will inherit; they grant nothing on the object itself.
const PLACEHOLDERS: [&str; 2] = ["S-1-3-0", "S-1-3-1"];

fn is_trusted(sid: &str) -> bool {
    TRUSTED.iter().any(|t| t.eq_ignore_ascii_case(sid))
}

/// The accounts, other than administrators, that could tamper with an object
/// given its owner and access list. Empty means only administrators can.
///
/// `aces` is `None` when the object has no access list at all, which Windows
/// reads as "everyone has full control".
pub fn untrusted_writers(owner: &str, aces: Option<&[Ace]>, kind: Kind) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |who: String| {
        if !out.contains(&who) {
            out.push(who);
        }
    };
    // An owner can always rewrite the access list, whatever it says.
    if !is_trusted(owner) {
        add(format!("{owner} (owner)"));
    }
    match aces {
        None => add("everyone (no access list)".to_string()),
        Some(list) => {
            for ace in list {
                if ace.allow
                    && !ace.inherit_only
                    && ace.mask & kind.dangerous() != 0
                    && !is_trusted(&ace.sid)
                    && !PLACEHOLDERS.contains(&ace.sid.as_str())
                {
                    add(ace.sid.clone());
                }
            }
        }
    }
    out
}

/// Names for the SIDs people recognise; the rest stay as SIDs.
pub fn sid_name(sid: &str) -> String {
    let sid_only = sid.trim_end_matches(" (owner)");
    let name = match sid_only {
        "S-1-1-0" => "Everyone",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "Users",
        "S-1-5-4" => "Interactive users",
        _ => return sid.to_string(),
    };
    if sid.ends_with(" (owner)") {
        format!("{name} (owner)")
    } else {
        name.to_string()
    }
}

#[cfg(windows)]
fn describe(who: &[String]) -> String {
    who.iter().map(|s| sid_name(s)).collect::<Vec<_>>().join(", ")
}

/// May an elevated ITriage start this program? Checks the file, its folder
/// and every folder above it.
#[cfg(windows)]
pub fn program(path: &Path) -> Result<(), String> {
    use crate::win::trust::security;
    if !path.is_absolute() {
        return Err(format!("{} isn't a full path", path.display()));
    }
    let check = |p: &Path, kind: Kind| -> Result<(), String> {
        let (owner, aces) = security(p)?;
        let who = untrusted_writers(&owner, aces.as_deref(), kind);
        if who.is_empty() {
            Ok(())
        } else {
            Err(format!("{} can be changed by {}", p.display(), describe(&who)))
        }
    };
    check(path, Kind::File)?;
    let mut kind = Kind::Folder;
    let mut dir = path.parent();
    while let Some(d) = dir {
        let is_root = d.parent().is_none();
        check(d, if is_root { Kind::Root } else { kind })?;
        kind = Kind::Ancestor;
        dir = d.parent();
    }
    Ok(())
}

/// May an elevated ITriage keep working files under this folder? The folder
/// and everything above it must be safe from renaming and replacing.
#[cfg(windows)]
pub fn folder_base(path: &Path) -> Result<(), String> {
    use crate::win::trust::security;
    let mut dir = Some(path);
    while let Some(d) = dir {
        let kind = if d.parent().is_none() { Kind::Root } else { Kind::Ancestor };
        let (owner, aces) = security(d)?;
        let who = untrusted_writers(&owner, aces.as_deref(), kind);
        if !who.is_empty() {
            return Err(format!("{} can be changed by {}", d.display(), describe(&who)));
        }
        dir = d.parent();
    }
    Ok(())
}

/// Is this the organisation's profile, or something a user dropped there?
/// Only the file is judged: its folder normally lets users add files, which
/// doesn't let them touch one an administrator made.
#[cfg(windows)]
pub fn profile(path: &Path) -> Result<(), String> {
    let (owner, aces) = crate::win::trust::security(path)?;
    let who = untrusted_writers(&owner, aces.as_deref(), Kind::File);
    if who.is_empty() {
        Ok(())
    } else {
        Err(format!("it can be changed by {}", describe(&who)))
    }
}

/// Root-owned, and not writable by group or others.
#[cfg(unix)]
pub fn unix_trusted(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

#[cfg(unix)]
pub fn profile(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    for p in [Some(path), path.parent()].into_iter().flatten() {
        let meta = std::fs::metadata(p).map_err(|e| format!("can't read {}: {e}", p.display()))?;
        if !unix_trusted(meta.uid(), meta.mode()) {
            return Err(format!("{} isn't owned by root, or others can write to it", p.display()));
        }
    }
    Ok(())
}

/// Programs run as root are looked up in the system's own folders, never in
/// a PATH that might start with a user's `~/bin`.
#[cfg(unix)]
pub fn system_program(name: &str) -> Option<std::path::PathBuf> {
    const DIRS: [&str; 6] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"];
    if name.contains('/') {
        return None;
    }
    DIRS.iter().map(|d| Path::new(d).join(name)).find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMINS: &str = "S-1-5-32-544";
    const SYSTEM: &str = "S-1-5-18";
    const TI: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    const USERS: &str = "S-1-5-32-545";
    const AUTH_USERS: &str = "S-1-5-11";
    const ALICE: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    const READ_EXECUTE: u32 = 0x1200a9;
    const MODIFY: u32 = 0x1301bf;
    const FULL: u32 = 0x1f01ff;

    fn allow(sid: &str, mask: u32) -> Ace {
        Ace { allow: true, inherit_only: false, mask, sid: sid.into() }
    }
    fn inherit_only(sid: &str, mask: u32) -> Ace {
        Ace { inherit_only: true, ..allow(sid, mask) }
    }

    /// What `C:\Program Files\Dell\CommandUpdate` looks like.
    fn program_files() -> Vec<Ace> {
        vec![
            allow(TI, FULL),
            allow(SYSTEM, FULL),
            allow(ADMINS, FULL),
            allow(USERS, READ_EXECUTE),
            inherit_only("S-1-3-0", GENERIC_ALL),
            allow("S-1-15-2-1", READ_EXECUTE), // ALL APPLICATION PACKAGES
        ]
    }

    #[test]
    fn program_files_is_trusted_at_every_level() {
        for kind in [Kind::File, Kind::Folder, Kind::Ancestor, Kind::Root] {
            assert_eq!(untrusted_writers(TI, Some(&program_files()), kind), Vec::<String>::new(), "{kind:?}");
        }
    }

    #[test]
    fn a_folder_made_at_the_top_of_c_is_not() {
        // C:\SWSetup\SP123456, extracted by an administrator: it inherits
        // "Authenticated Users: Modify" from the drive's root.
        let swsetup = vec![allow(ADMINS, FULL), allow(SYSTEM, FULL), allow(USERS, READ_EXECUTE), allow(AUTH_USERS, MODIFY)];
        assert_eq!(untrusted_writers(ADMINS, Some(&swsetup), Kind::Folder), vec![AUTH_USERS.to_string()]);
        assert_eq!(untrusted_writers(ADMINS, Some(&swsetup), Kind::File), vec![AUTH_USERS.to_string()]);
        assert_eq!(untrusted_writers(ADMINS, Some(&swsetup), Kind::Ancestor), vec![AUTH_USERS.to_string()], "Modify includes Delete");
    }

    #[test]
    fn the_drive_root_and_programdata_pass_as_ancestors_only() {
        // C:\ lets signed-in users create folders (append) but not delete
        // or rename what's there.
        let root = vec![allow(ADMINS, FULL), allow(SYSTEM, FULL), allow(USERS, READ_EXECUTE), allow(AUTH_USERS, FILE_APPEND_DATA), inherit_only(AUTH_USERS, MODIFY)];
        assert!(untrusted_writers(TI, Some(&root), Kind::Root).is_empty());
        // C:\ProgramData lets users add files and folders.
        let programdata = vec![allow(SYSTEM, FULL), allow(ADMINS, FULL), allow(USERS, READ_EXECUTE | FILE_WRITE_DATA | FILE_APPEND_DATA), inherit_only("S-1-3-0", GENERIC_ALL)];
        assert!(untrusted_writers(SYSTEM, Some(&programdata), Kind::Ancestor).is_empty());
        assert_eq!(untrusted_writers(SYSTEM, Some(&programdata), Kind::Folder), vec![USERS.to_string()], "but a program can't live directly in it");
    }

    #[test]
    fn a_users_own_file_or_folder_is_never_trusted() {
        // A profile.toml a user dropped into C:\ProgramData\itriage: they
        // own it, so they can change it whatever the access list says.
        let dropped = vec![allow(SYSTEM, FULL), allow(ADMINS, FULL), allow(USERS, READ_EXECUTE), allow(ALICE, FULL)];
        let who = untrusted_writers(ALICE, Some(&dropped), Kind::File);
        assert_eq!(who, vec![format!("{ALICE} (owner)"), ALICE.to_string()]);
        // Even with a spotless access list, an untrusted owner fails.
        assert_eq!(untrusted_writers(ALICE, Some(&program_files()), Kind::File).len(), 1);
        // The one an administrator deployed there passes.
        let deployed = vec![allow(SYSTEM, FULL), allow(ADMINS, FULL), allow(USERS, READ_EXECUTE)];
        assert!(untrusted_writers(ADMINS, Some(&deployed), Kind::File).is_empty());
    }

    #[test]
    fn no_access_list_means_everyone() {
        assert_eq!(untrusted_writers(ADMINS, None, Kind::File), vec!["everyone (no access list)".to_string()]);
        // A deny entry never grants anything.
        let deny = Ace { allow: false, ..allow(USERS, FULL) };
        assert!(untrusted_writers(ADMINS, Some(&[deny]), Kind::File).is_empty());
    }

    #[test]
    fn names_the_usual_suspects() {
        assert_eq!(sid_name(AUTH_USERS), "Authenticated Users");
        assert_eq!(sid_name("S-1-5-32-545 (owner)"), "Users (owner)");
        assert_eq!(sid_name(ALICE), ALICE);
    }

    #[cfg(unix)]
    #[test]
    fn unix_rule_is_root_and_not_shared() {
        assert!(unix_trusted(0, 0o100644));
        assert!(unix_trusted(0, 0o40755));
        assert!(!unix_trusted(1000, 0o100644), "a user's own file");
        assert!(!unix_trusted(0, 0o100664), "group-writable");
        assert!(!unix_trusted(0, 0o40777), "world-writable");
        assert!(system_program("sh").is_some());
        assert!(system_program("../bin/sh").is_none() && system_program("definitely-not-a-tool-xyz").is_none());
    }

    /// The real thing, on a real Windows machine (CI runs this).
    #[cfg(windows)]
    #[test]
    fn windows_judges_real_files() {
        let cmd = crate::win::dirs::system32().join("cmd.exe");
        assert_eq!(program(&cmd), Ok(()), "Windows' own tools are trusted");
        let mine = std::env::temp_dir().join(format!("itriage-trust-{}.exe", std::process::id()));
        std::fs::write(&mine, b"x").unwrap();
        let verdict = program(&mine);
        let _ = std::fs::remove_file(&mine);
        assert!(verdict.is_err(), "a file in this account's temp folder isn't: {verdict:?}");
    }
}
