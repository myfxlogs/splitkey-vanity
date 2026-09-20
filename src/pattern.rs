// pattern.rs — pattern grammar and matching (spec/split-key.md §3.1, §4)
//
// Grammar (§3.1):
//   repeat:<n>   tail ≥ n identical chars          (4 ≤ n ≤ 34)
//   pair:<k>     tail 2k chars = k adjacent pairs  (k ≥ 2, adjacent groups
//                differ: A≠B, B≠C — A=C allowed; e.g. pair:2 = AABB)
//   alt:2        tail 4 chars XYXY (X≠Y)
//   suffix:<s>   literal tail, s ∈ base58 alphabet, 2 ≤ |s| ≤ 8
//
// Patterns compare semantically as parsed values, never by raw string.

use std::fmt;

/// Parsed order pattern (§3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Pattern {
    /// `repeat:<n>` — trailing run of ≥ n identical base58 chars.
    Repeat(u32),
    /// `pair:<k>` — trailing 2k chars form k adjacent pairs, adjacent
    /// groups holding different characters (AABBCC…, A=C allowed).
    Pair(u32),
    /// `alt:2` — trailing 4 chars XYXY with X≠Y.
    Alt,
    /// `suffix:<s>` — literal base58 tail (e.g. `suffix:8888` = …8888).
    Suffix(String),
}

/// TRON base58 alphabet — no `0 O I l`.
const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// §3.1 reachability yardstick: E = tail-space / hits. E ≤ 58⁶ ships
/// silently, E ≤ 58⁸ warns, E > 58⁸ is undeliverable → parse-rejected
/// for new types (repeat keeps its legacy n ≥ 29 rule instead).
const E_WARN: f64 = 38_068_692_544.0; // 58^6
const E_REJECT: f64 = 128_063_081_718_016.0; // 58^8

impl Pattern {
    /// Parse `type:value`. Accepts leading zeros in numeric fields (canonical
    /// emitters never produce them) and a bare `<n>` as shorthand for
    /// `repeat:<n>`; rejects unknown types, `|`, and out-of-range values.
    pub fn parse(s: &str) -> Result<Pattern, String> {
        let s = s.trim();
        if s.contains('|') {
            return Err("pattern must not contain '|' (reserved order delimiter)".into());
        }
        let (ty, value) = match s.split_once(':') {
            Some((ty, value)) => (ty, value),
            // Bare `<n>` input sugar — unambiguous: all other types carry a
            // `type:` prefix.
            None if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => ("repeat", s),
            None => {
                return Err(format!(
                    "invalid pattern {s:?} (want repeat:<n>, pair:<k>, alt:2, suffix:<s>, or <n>)"
                ))
            }
        };
        let p = match ty {
            "repeat" => {
                let n: u32 = value
                    .parse()
                    .map_err(|_| format!("invalid repeat count {value:?}"))?;
                if !(4..=34).contains(&n) {
                    return Err(format!("repeat count {n} out of range (need 4 ≤ n ≤ 34)"));
                }
                Pattern::Repeat(n)
            }
            "pair" => {
                let k: u32 = value
                    .parse()
                    .map_err(|_| format!("invalid pair count {value:?}"))?;
                if k < 2 {
                    return Err(format!("pair count {k} out of range (need k ≥ 2)"));
                }
                Pattern::Pair(k)
            }
            "alt" => {
                if value != "2" {
                    return Err(format!("invalid alt {value:?} (only alt:2 exists)"));
                }
                Pattern::Alt
            }
            "suffix" => {
                if !(2..=8).contains(&value.len()) {
                    return Err(format!(
                        "suffix length {} out of range (need 2 ≤ len ≤ 8)",
                        value.len()
                    ));
                }
                if !value.chars().all(|c| B58.contains(c)) {
                    return Err(format!(
                        "suffix {value:?} contains non-base58 characters (no 0 O I l)"
                    ));
                }
                Pattern::Suffix(value.to_string())
            }
            _ => {
                return Err(format!(
                    "unknown pattern type {ty:?} (want repeat, pair, alt, suffix)"
                ))
            }
        };
        // §3.1 reachability gate for new types — repeat keeps its own
        // legacy bound (4..=34) and the §3.1 n ≥ 29 warning rule.
        if !matches!(p, Pattern::Repeat(_)) && p.expected_iterations() > E_REJECT {
            return Err(format!(
                "pattern {} is undeliverable (§3.1: expected work > 58^8)",
                p.canonical()
            ));
        }
        Ok(p)
    }

    /// Canonical string form — decimal, no leading zeros.
    pub fn canonical(&self) -> String {
        match self {
            Pattern::Repeat(n) => format!("repeat:{n}"),
            Pattern::Pair(k) => format!("pair:{k}"),
            Pattern::Alt => "alt:2".into(),
            Pattern::Suffix(s) => format!("suffix:{s}"),
        }
    }

    /// Expected search iterations E = 58^(tail window) / favorable outcomes.
    /// The single reachability yardstick for all types (§3.1).
    pub fn expected_iterations(&self) -> f64 {
        const B: f64 = 58.0;
        match self {
            Pattern::Repeat(n) => B.powi(*n as i32 - 1),
            // k pairs on 2k tail chars: 58·57^(k-1) hits of 58^2k tails.
            Pattern::Pair(k) => B.powi(2 * *k as i32) / (B * 57f64.powi(*k as i32 - 1)),
            Pattern::Alt => B.powi(4) / (B * 57.0),
            Pattern::Suffix(s) => B.powi(s.len() as i32),
        }
    }

    /// §3.1 reachability: repeat warns at n ≥ 29 (legacy rule); new types
    /// warn when expected work exceeds 58⁶.
    pub fn needs_reachability_warning(&self) -> bool {
        match self {
            Pattern::Repeat(n) => *n >= 29,
            _ => self.expected_iterations() > E_WARN,
        }
    }

    /// Chars from the tail needed to evaluate the match — the base58
    /// encoder only materializes this many trailing digits.
    pub fn tail_window(&self) -> usize {
        match self {
            Pattern::Repeat(n) => *n as usize,
            Pattern::Pair(k) => 2 * *k as usize,
            Pattern::Alt => 4,
            Pattern::Suffix(s) => s.len(),
        }
    }

    /// §4 check semantics on the full 34-char base58 string.
    pub fn matches(&self, addr: &str) -> bool {
        let t: Vec<char> = addr.chars().collect();
        let n = t.len();
        match self {
            Pattern::Repeat(k) => trailing_repeat(addr) >= *k as usize,
            Pattern::Pair(k) => {
                let k = *k as usize;
                if n < 2 * k {
                    return false;
                }
                (0..k).all(|i| t[n - 1 - 2 * i] == t[n - 2 - 2 * i])
                    && (0..k - 1).all(|i| t[n - 1 - 2 * i] != t[n - 3 - 2 * i])
            }
            Pattern::Alt => {
                n >= 4 && t[n - 4] == t[n - 2] && t[n - 3] == t[n - 1] && t[n - 2] != t[n - 1]
            }
            Pattern::Suffix(s) => addr.ends_with(s.as_str()),
        }
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
    fn parses_new_types() {
        assert_eq!(Pattern::parse("pair:2").unwrap(), Pattern::Pair(2));
        assert_eq!(Pattern::parse("pair:5").unwrap(), Pattern::Pair(5));
        assert_eq!(Pattern::parse("alt:2").unwrap(), Pattern::Alt);
        assert_eq!(
            Pattern::parse("suffix:8888").unwrap(),
            Pattern::Suffix("8888".into())
        );
        assert_eq!(
            Pattern::parse("suffix:Ab").unwrap(),
            Pattern::Suffix("Ab".into())
        );
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
            "pair",
            "pair:",
            "pair:1",
            "pair:x",
            "pair:2|x",
            "alt",
            "alt:1",
            "alt:3",
            "suffix",
            "suffix:",
            "suffix:8",
            "suffix:888888888",
            "suffix:0OIl",
            "suffix:88|x",
            "suffix:88:9",
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
    fn reachability_rejects_undeliverable_new_types() {
        // E > 58^8 → parse-rejected (spec §3.1).
        // pair:8: 58^16 tails / 58·57^7 hits ≈ 58^8·(58/57)^7 > 58^8.
        assert!(Pattern::parse("pair:8").is_err());
        // pair:7 ≈ 58^7·1.11 — allowed, warn band.
        assert!(Pattern::parse("pair:7").is_ok());
        // suffix len ≤ 8 → E ≤ 58^8, all allowed.
        assert!(Pattern::parse("suffix:12345678").is_ok());
    }

    #[test]
    fn canonical_form_has_no_leading_zeros() {
        assert_eq!(Pattern::parse("repeat:08").unwrap().canonical(), "repeat:8");
        assert_eq!(Pattern::parse("pair:03").unwrap().canonical(), "pair:3");
        assert_eq!(
            Pattern::parse("suffix:8888").unwrap().canonical(),
            "suffix:8888"
        );
    }

    #[test]
    fn reachability_warning_threshold() {
        assert!(!Pattern::Repeat(28).needs_reachability_warning());
        assert!(Pattern::Repeat(29).needs_reachability_warning());
        // New types: E > 58^6 warns.
        assert!(!Pattern::Pair(2).needs_reachability_warning());
        assert!(!Pattern::parse("suffix:666666")
            .unwrap()
            .needs_reachability_warning());
        assert!(Pattern::parse("suffix:7777777")
            .unwrap()
            .needs_reachability_warning());
        assert!(Pattern::parse("pair:7").unwrap().needs_reachability_warning());
    }

    #[test]
    fn expected_iterations_matches_probability_table() {
        // §3.1 table: pair:2 ≈ 58³/57, suffix:4 = 58⁴, repeat:4 = 58³.
        let e = |p: &str| Pattern::parse(p).unwrap().expected_iterations();
        assert!((e("pair:2") - 58f64.powi(3) / 57.0).abs() < 1.0);
        assert_eq!(e("alt:2"), e("pair:2"));
        assert_eq!(e("suffix:4444"), 58f64.powi(4));
        assert_eq!(e("repeat:4"), 58f64.powi(3));
        assert_eq!(e("suffix:333"), e("repeat:4"));
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
    fn pair_match_semantics() {
        let p = Pattern::Pair(2);
        assert!(p.matches("TxAABB")); // canonical AABB
        assert!(p.matches("T1188")); // 1,8 both base58 pairs
        assert!(!p.matches("TxAAAA")); // A=B → that's repeat:4, not AABB
        assert!(!p.matches("TxAABC")); // second group not a pair
        assert!(!p.matches("TxABBA")); // ABBA is not AABB
        let p3 = Pattern::Pair(3);
        assert!(p3.matches("TxAABBCC"));
        assert!(p3.matches("TxAABBAA")); // A=C allowed (adjacent differ only)
        assert!(!p3.matches("TxAABBCA")); // last pair CA ≠ CC
        assert!(!p3.matches("TxAAAABB")); // group 2 = AA == group 3's AA? AA vs BB ok but group1 AA == group2 AA → fail
    }

    #[test]
    fn alt_match_semantics() {
        let p = Pattern::Alt;
        assert!(p.matches("TxABAB"));
        assert!(p.matches("Tx1212"));
        assert!(!p.matches("TxAAAA")); // X=Y
        assert!(!p.matches("TxAABB")); // AABB ≠ ABAB
        assert!(!p.matches("TxABAC"));
    }

    #[test]
    fn suffix_match_semantics() {
        let p = Pattern::parse("suffix:8888").unwrap();
        assert!(p.matches("Tabc8888"));
        assert!(p.matches("T8888"));
        assert!(!p.matches("Tabc8887"));
        assert!(!p.matches("Tabc888"));
        let p2 = Pattern::parse("suffix:Ab").unwrap();
        assert!(p2.matches("TxAb"));
        assert!(!p2.matches("TxaB"));
    }

    #[test]
    fn matching_counts_leading_t() {
        // The match runs on the full base58 string — trailing 'T's count.
        assert!(Pattern::Repeat(4).matches("TabcTTTT"));
        assert!(Pattern::parse("suffix:TT").unwrap().matches("TabTT"));
    }

    #[test]
    fn tail_window_sizes() {
        assert_eq!(Pattern::Repeat(8).tail_window(), 8);
        assert_eq!(Pattern::Pair(3).tail_window(), 6);
        assert_eq!(Pattern::Alt.tail_window(), 4);
        assert_eq!(Pattern::parse("suffix:8888").unwrap().tail_window(), 4);
    }
}
