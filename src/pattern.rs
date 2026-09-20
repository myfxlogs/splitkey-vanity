// pattern.rs — pattern grammar and matching (spec/split-key.md §3.1, §4)
//
// v1 supports `repeat:<n>` only: the address ends with ≥ n identical base58
// characters, matched on the full 34-char string including the leading 'T'.
// Patterns compare semantically as the parsed (type, n) tuple, never by raw
// string.

use std::fmt;

/// Parsed order pattern. v1: `repeat:<n>` with 4 ≤ n ≤ 34.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pattern {
    Repeat(u32),
}

impl Pattern {
    /// Parse `type:value`. Accepts leading zeros in `<n>` (canonical emitters
    /// never produce them) and a bare `<n>` as shorthand for `repeat:<n>`;
    /// rejects unknown types, `|`, and out-of-range n.
    pub fn parse(s: &str) -> Result<Pattern, String> {
        let s = s.trim();
        if s.contains('|') {
            return Err("pattern must not contain '|' (reserved order delimiter)".into());
        }
        let (ty, value) = match s.split_once(':') {
            Some((ty, value)) => (ty, value),
            // Bare `<n>` input sugar — unambiguous: future pattern types
            // always carry a `type:` prefix.
            None if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => ("repeat", s),
            None => return Err(format!("invalid pattern {s:?} (want `repeat:<n>` or `<n>`)")),
        };
        if ty != "repeat" {
            return Err(format!(
                "unknown pattern type {ty:?} (v1 supports `repeat` only)"
            ));
        }
        let n: u32 = value
            .parse()
            .map_err(|_| format!("invalid repeat count {value:?}"))?;
        if !(4..=34).contains(&n) {
            return Err(format!("repeat count {n} out of range (need 4 ≤ n ≤ 34)"));
        }
        Ok(Pattern::Repeat(n))
    }

    /// Canonical string form — decimal, no leading zeros.
    pub fn canonical(&self) -> String {
        match self {
            Pattern::Repeat(n) => format!("repeat:{n}"),
        }
    }

    /// §3.1 reachability note: orders with n ≥ 29 are effectively
    /// undeliverable; buyer tools SHOULD warn.
    pub fn needs_reachability_warning(&self) -> bool {
        matches!(self, Pattern::Repeat(n) if *n >= 29)
    }

    /// §4 check semantics: `addr` ends with ≥ n identical base58 characters.
    pub fn matches(&self, addr: &str) -> bool {
        let Pattern::Repeat(n) = self;
        trailing_repeat(addr) >= *n as usize
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// Length of the trailing run of identical characters in `addr`.
fn trailing_repeat(addr: &str) -> usize {
    let mut count = 0;
    let mut last = None;
    for c in addr.chars().rev() {
        if last == Some(c) || last.is_none() {
            last = Some(c);
            count += 1;
        } else {
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_and_leading_zeros() {
        assert_eq!(Pattern::parse("repeat:8").unwrap(), Pattern::Repeat(8));
        assert_eq!(Pattern::parse("repeat:08").unwrap(), Pattern::Repeat(8));
        assert_eq!(Pattern::parse(" repeat:4 ").unwrap(), Pattern::Repeat(4));
    }

    #[test]
    fn bare_n_is_repeat_shorthand() {
        // Buyer-facing input sugar: a bare integer means `repeat:<n>`.
        assert_eq!(Pattern::parse("4").unwrap(), Pattern::Repeat(4));
        assert_eq!(Pattern::parse("8").unwrap(), Pattern::Repeat(8));
        assert_eq!(Pattern::parse("34").unwrap(), Pattern::Repeat(34));
        assert_eq!(Pattern::parse(" 6 ").unwrap(), Pattern::Repeat(6));
        assert_eq!(Pattern::parse("08").unwrap(), Pattern::Repeat(8));
    }

    #[test]
    fn rejects_illegal_forms() {
        for bad in [
            "prefix:abc",
            "repeat",
            "repeat:",
            "repeat:x",
            "repeat:-4",
            "repeat:3",
            "repeat:35",
            "repeat:4|x",
            "Repeat:8",
            "repeat:8:9",
            "",
            "0",
            "3",
            "35",
            "-4",
            "x",
            "4|x",
            "8:9",
        ] {
            assert!(Pattern::parse(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn canonical_form_has_no_leading_zeros() {
        assert_eq!(Pattern::parse("repeat:08").unwrap().canonical(), "repeat:8");
    }

    #[test]
    fn reachability_warning_threshold() {
        assert!(!Pattern::Repeat(28).needs_reachability_warning());
        assert!(Pattern::Repeat(29).needs_reachability_warning());
    }

    #[test]
    fn repeat_match_boundaries() {
        let p = Pattern::Repeat(4);
        assert!(p.matches("Tabcdddd")); // run of 4 ≥ 4
        assert!(p.matches("Tabcddddd")); // run of 5 ≥ 4
        assert!(!p.matches("Tabcddde")); // run of 3 < 4
        assert!(!p.matches("Tddddx"));
    }

    #[test]
    fn matching_counts_leading_t() {
        // The match runs on the full base58 string — trailing 'T's count.
        assert!(Pattern::Repeat(4).matches("TabcTTTT"));
    }
}
