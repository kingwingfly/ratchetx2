//! Searching text with a regular expression, in linear time whatever the pattern, so that no
//! search keeps a page waiting: the matches, as offsets in UTF-16 code units, as a page counts
//! the text of its nodes.

use std::borrow::Cow;

use regex::RegexBuilder;

use crate::Worker;
use crate::rpc::{Method, Request, Response, WorkerService};

/// The most matches examined and returned: the first are the ones to go through.
pub use crate::rpc::MATCHES_MAX;
/// Maximum byte length of a raw search pattern (4 KiB).
pub const PATTERN_MAX_BYTES: usize = 4 * 1024;
/// The most memory a pattern's compiled form may take, in bytes (1 MiB).
const PATTERN_SIZE_MAX: usize = 1 << 20;
/// Maximum memory used by the lazy DFA cache (2 MiB).
const DFA_SIZE_MAX: usize = 2 << 20;
/// Maximum regex AST nesting depth.
const NEST_LIMIT: u32 = 128;

pub use crate::rpc::SearchFound as Found;

/// The matches of `pattern` in `text`: a regular expression, or else the text as written, in
/// either case ignoring case unless `case` says otherwise. An invalid or oversized pattern says
/// why.
pub fn find(text: &str, pattern: &str, case: bool, regex: bool) -> Result<Found, String> {
    if pattern.len() > PATTERN_MAX_BYTES {
        return Err("the search pattern is too long".to_string());
    }
    u32::try_from(text.len()).map_err(|_| "the text is too large to search".to_string())?;
    if pattern.is_empty() {
        return Ok(Found {
            matches: Vec::new(),
            more: false,
        });
    }
    let pattern = if regex {
        Cow::Borrowed(pattern)
    } else {
        Cow::Owned(regex::escape(pattern))
    };
    let regex = RegexBuilder::new(&pattern)
        .case_insensitive(!case)
        .multi_line(true)
        .size_limit(PATTERN_SIZE_MAX)
        .dfa_size_limit(DFA_SIZE_MAX)
        .nest_limit(NEST_LIMIT)
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
    for (examined, found) in regex.find_iter(text).enumerate() {
        if examined == MATCHES_MAX {
            more = true;
            break;
        }
        if found.is_empty() {
            continue;
        }
        let start = advance(found.start());
        let end = advance(found.end());
        matches.push((start, end));
    }
    Ok(Found { matches, more })
}

/// Stateless [`WorkerService`] for text/regex search requests.
#[derive(Debug, Default, Clone, Copy)]
pub struct SearchService;

impl WorkerService for SearchService {
    fn accepts(&self, method: Method) -> bool {
        method.is_served_by(Worker::Search)
    }

    fn handle(&mut self, req: Request) -> Result<Response, String> {
        match req {
            Request::Find {
                text,
                pattern,
                case,
                regex,
            } => find(&text, &pattern, case, regex).map(Response::Found),
            other => Err(format!("no method {}", other.method().as_str())),
        }
    }
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
    fn empty_pattern_returns_empty_without_scanning() {
        for regex in [false, true] {
            let found = find("abcdef", "", true, regex).unwrap();
            assert!(found.matches.is_empty());
            assert!(!found.more);
        }
    }

    #[test]
    fn empty_matches_are_skipped_and_capped() {
        let small = find("abc", "x*", true, true).unwrap();
        assert!(small.matches.is_empty());
        assert!(!small.more);

        // Zero-width matches must still trip the MATCHES_MAX work cap rather than scanning
        // arbitrarily long inputs unchecked.
        let large = "b".repeat(MATCHES_MAX + 500) + "a";
        let found = find(&large, "a*", true, true).unwrap();
        assert!(found.matches.is_empty());
        assert!(found.more);
    }

    #[test]
    fn rejects_oversized_and_deeply_nested_patterns() {
        let too_long = "a".repeat(PATTERN_MAX_BYTES + 1);
        assert!(find("aaa", &too_long, true, false).is_err());
        assert!(find("aaa", &too_long, true, true).is_err());

        let exact = "a".repeat(PATTERN_MAX_BYTES);
        assert!(find("aaa", &exact, true, false).is_ok());

        let deep = format!("{}a{}", "(".repeat(200), ")".repeat(200));
        assert!(find("a", &deep, true, true).is_err());
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

    #[test]
    fn search_service_dispatches_and_rejects_other_methods() {
        let mut service = SearchService;
        assert!(service.accepts(Method::Find));
        assert!(!service.accepts(Method::Open));
        let reply = service
            .handle(Request::Find {
                text: "hello world".into(),
                pattern: "world".into(),
                case: true,
                regex: false,
            })
            .unwrap();
        assert_eq!(
            reply,
            Response::Found(Found {
                matches: vec![(6, 11)],
                more: false,
            })
        );
        assert!(service.handle(Request::Close { doc_id: 1 }).is_err());
    }
}
