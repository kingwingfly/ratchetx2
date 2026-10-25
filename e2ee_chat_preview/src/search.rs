//! Searching text with a regular expression, in linear time whatever the pattern, so that no
//! search keeps a page waiting: the matches, as offsets in UTF-16 code units, as a page counts
//! the text of its nodes.

use regex::RegexBuilder;

/// The most matches found: the first are the ones to go through.
pub const MATCHES_MAX: usize = 10_000;
/// The most memory a pattern's compiled form may take, in bytes.
const PATTERN_SIZE_MAX: usize = 1 << 20;

/// What a search found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Each match's start and end, in UTF-16 code units, in order; none is empty.
    pub matches: Vec<(u32, u32)>,
    /// Whether there are more than [`MATCHES_MAX`].
    pub more: bool,
}

/// The matches of `pattern` in `text`: a regular expression, or else the text as written, in
/// either case ignoring case unless `case` says otherwise. An invalid pattern says why.
pub fn find(text: &str, pattern: &str, case: bool, regex: bool) -> Result<Found, String> {
    let pattern = if regex {
        pattern.to_string()
    } else {
        regex::escape(pattern)
    };
    let regex = RegexBuilder::new(&pattern)
        .case_insensitive(!case)
        .multi_line(true)
        .size_limit(PATTERN_SIZE_MAX)
        .build()
        .map_err(|e| e.to_string())?;
    let mut matches = Vec::new();
    let mut more = false;
    // Where the last match ended, in bytes and in UTF-16 code units.
    let (mut bytes, mut units) = (0, 0u32);
    let mut advance = |to: usize| {
        units += text[bytes..to].encode_utf16().count() as u32;
        bytes = to;
        units
    };
    for found in regex.find_iter(text).filter(|found| !found.is_empty()) {
        if matches.len() == MATCHES_MAX {
            more = true;
            break;
        }
        let start = advance(found.start());
        let end = advance(found.end());
        matches.push((start, end));
    }
    Ok(Found { matches, more })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_expressions() {
        let found = find("fn main() {}\nfn other() {}", r"fn \w+", true, true).unwrap();
        assert_eq!(found.matches, [(0, 7), (13, 21)]);
        assert!(!found.more);
    }

    #[test]
    fn plain_text_and_case() {
        // A pattern's special characters are only text when it is not a regular expression.
        assert_eq!(
            find("a.b axb", "a.b", true, false).unwrap().matches,
            [(0, 3)]
        );
        assert_eq!(
            find("a.b axb", "a.b", true, true).unwrap().matches,
            [(0, 3), (4, 7)]
        );
        assert_eq!(
            find("Fn fn", "fn", false, false).unwrap().matches,
            [(0, 2), (3, 5)]
        );
        assert_eq!(find("Fn fn", "fn", true, false).unwrap().matches, [(3, 5)]);
    }

    #[test]
    fn offsets_count_utf16_code_units() {
        // é is one code unit, 世 one, 😀 two, as a page counts them.
        let found = find("é世😀x", "x", true, true).unwrap();
        assert_eq!(found.matches, [(4, 5)]);
        let found = find("a😀b😀", "😀", true, true).unwrap();
        assert_eq!(found.matches, [(1, 3), (4, 6)]);
    }

    #[test]
    fn lines_start_and_end_anywhere() {
        let found = find("one\ntwo", "^t", true, true).unwrap();
        assert_eq!(found.matches, [(4, 5)]);
    }

    #[test]
    fn empty_matches_are_skipped() {
        assert!(find("abc", "x*", true, true).unwrap().matches.is_empty());
    }

    #[test]
    fn invalid_patterns_say_why() {
        assert!(find("abc", "(", true, true).is_err());
        // As text, it is fine.
        assert!(find("a(b", "(", true, false).unwrap().matches == [(1, 2)]);
    }

    #[test]
    fn matches_stop_at_the_most() {
        let text = "a".repeat(MATCHES_MAX + 5);
        let found = find(&text, "a", true, true).unwrap();
        assert_eq!(found.matches.len(), MATCHES_MAX);
        assert!(found.more);
    }

    #[test]
    fn no_pattern_backtracks_for_long() {
        // Exponential for a backtracking engine; linear here.
        let text = format!("{}!", "a".repeat(100_000));
        let started = std::time::Instant::now();
        assert!(
            find(&text, "(a+)+$", true, true)
                .unwrap()
                .matches
                .is_empty()
        );
        assert!(started.elapsed().as_secs() < 5);
    }
}
