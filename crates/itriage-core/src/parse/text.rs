//! Text clean-up shared by the parsers and the streaming runner.

/// Remove ANSI/VT escape sequences: CSI (`ESC [ … final`), OSC
/// (`ESC ] … BEL` or `ESC ] … ESC \`), and two-character escapes.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('[') => {
                chars.next();
                // parameter/intermediate bytes, then one final byte in @..~
                for n in chars.by_ref() {
                    if ('@'..='~').contains(&n) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                while let Some(n) = chars.next() {
                    if n == '\x07' {
                        break;
                    }
                    if n == '\x1b' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

/// Turn one raw output line into something worth showing in a live log, or
/// `None` for noise: blank lines, spinner frames, and progress bars.
pub fn clean_progress_line(raw: &str) -> Option<String> {
    let s = strip_ansi(raw);
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    const BAR_GLYPHS: &[char] = &['█', '▓', '▒', '░', '■', '□', '▌', '▐'];
    const SPINNER: &[char] = &['-', '\\', '|', '/', '=', '#', '>', ' '];
    if t.chars().any(|c| BAR_GLYPHS.contains(&c)) {
        return None;
    }
    if t.chars().all(|c| SPINNER.contains(&c)) {
        return None;
    }
    Some(t.to_string())
}

/// A grouping key for log messages that differ only in their variable parts.
/// Any word containing a digit (PIDs, ports, counters, hex addresses, GUID
/// segments, IP octets, `sda1`) becomes `#`, and whitespace runs collapse, so
/// "pid 4812 crashed at 0x7ffe12" and "pid 977 crashed at 0x1a2b" land in one
/// group.
pub fn normalize_message(msg: &str) -> String {
    fn flush(word: &mut String, out: &mut String) {
        if word.is_empty() {
            return;
        }
        if word.chars().any(|c| c.is_ascii_digit()) {
            out.push('#');
        } else {
            out.push_str(word);
        }
        word.clear();
    }

    let mut out = String::with_capacity(msg.len());
    let mut word = String::new();
    let mut prev_space = false;
    for c in msg.chars() {
        if c.is_alphanumeric() || c == '_' {
            word.push(c);
            prev_space = false;
            continue;
        }
        flush(&mut word, &mut out);
        if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    flush(&mut word, &mut out);
    truncate_chars(out.trim(), 160)
}

/// Cut to at most `max` characters, ending with `…` when something was cut.
pub fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut cut: String = s.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// First non-blank line, trimmed.
pub fn first_line(s: &str) -> &str {
    s.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escape_codes() {
        assert_eq!(strip_ansi("\x1b[2K\x1b[1;32mOK\x1b[0m done"), "OK done");
        assert_eq!(strip_ansi("\x1b]0;title\x07text"), "text");
    }

    #[test]
    fn filters_progress_noise() {
        assert_eq!(clean_progress_line("   -  "), None);
        assert_eq!(clean_progress_line("  \\ "), None);
        assert_eq!(clean_progress_line("  ██████████▒▒▒▒▒  2.00 MB / 5.00 MB"), None);
        assert_eq!(clean_progress_line(""), None);
        assert_eq!(
            clean_progress_line("  Successfully installed  "),
            Some("Successfully installed".to_string())
        );
    }

    #[test]
    fn normalizes_variable_parts() {
        assert_eq!(
            normalize_message("Process 4812 crashed at 0x7ffe12"),
            normalize_message("Process 977 crashed at 0x1a2b")
        );
        assert_eq!(normalize_message("Process 4812 crashed at 0x7ffe12"), "Process # crashed at #");
        assert_eq!(
            normalize_message("link down on 192.168.1.5 {331c3b3a-2005-44c2}"),
            "link down on #.#.#.# {#-#-#}"
        );
        assert_eq!(normalize_message("a   b\tc"), "a b c");
    }

    #[test]
    fn truncates_on_char_boundaries() {
        assert_eq!(truncate_chars("héllo wörld", 6), "héllo…");
        assert_eq!(truncate_chars("short", 10), "short");
        assert_eq!(first_line("\n  \n  first \nsecond"), "first");
    }
}
