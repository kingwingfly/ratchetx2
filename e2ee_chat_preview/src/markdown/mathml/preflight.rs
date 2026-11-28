/// Maximum raw TeX input bytes accepted for a single MathML expression before falling back to
/// escaped raw TeX.
const MATH_INPUT_MAX: usize = 8 * 1024;
/// Maximum zero-event TeX directives allowed in one expression so recursive `pulldown-latex`
/// `Parser::next()` calls cannot overflow the `wasm32` call stack.
const MATH_DIRECTIVES_MAX: usize = 32;
/// Maximum `%` comments allowed in one TeX expression (`pulldown-latex` lexes comments recursively).
const MATH_COMMENTS_MAX: usize = 64;
/// Maximum consecutive or chained unbraced control-sequence arguments (e.g. `\not\not...`,
/// `\frac{1}\frac{1}...`, `\sqrt[]\sqrt[]...`) allowed so `pulldown-latex`'s `handle_argument`
/// recursion cannot overflow the `wasm32` call stack.
const MATH_CONSECUTIVE_CS_MAX: usize = 16;
/// Maximum empty brace/bracket groups (`{}` / `[]`) allowed so `pulldown-latex`'s `Parser::next()`
/// cannot stack-overflow draining consecutive empty `SubGroup` entries.
const MATH_EMPTY_GROUPS_MAX: usize = 32;
/// Maximum total `{` brace groups allowed in one TeX expression so nested `{{...}}` cannot
/// bypass flat empty-group counting and stack-overflow `pulldown-latex`.
const MATH_GROUPS_MAX: usize = 256;
/// Maximum brace nesting depth allowed in raw TeX before parsing (prevents deep `wasm32` stack
/// recursion before reaching `MathmlRenderer`).
const MATH_BRACE_DEPTH_MAX: usize = 64;

/// Advance `pos` past ASCII whitespace and `%...\n` comments, returning the next balanced `{...}`
/// group slice (without outer braces) if `bytes[*pos] == b'{'`. Comments inside `{...}` are
/// skipped to `\n` to match `pulldown-latex`'s `lex::group_content` (returning `None` if a comment
/// runs to EOF without closing the group).
fn next_braced_arg<'a>(tex: &'a str, pos: &mut usize) -> Option<&'a str> {
    let bytes = tex.as_bytes();
    while *pos < bytes.len() {
        if bytes[*pos].is_ascii_whitespace() {
            *pos += 1;
        } else if bytes[*pos] == b'%' {
            while *pos < bytes.len() && bytes[*pos] != b'\n' {
                *pos += 1;
            }
        } else {
            break;
        }
    }
    if bytes.get(*pos) != Some(&b'{') {
        return None;
    }
    *pos += 1;
    let start = *pos;
    let mut depth = 1usize;
    while *pos < bytes.len() {
        match bytes[*pos] {
            b'\\' => {
                *pos += 1;
                if *pos < bytes.len() {
                    let ch_len = tex[*pos..].chars().next().map_or(1, char::len_utf8);
                    *pos += ch_len;
                }
            }
            b'%' => {
                while *pos < bytes.len() && bytes[*pos] != b'\n' {
                    *pos += 1;
                }
                if *pos >= bytes.len() {
                    return None;
                }
                *pos += 1;
            }
            b'{' => {
                depth += 1;
                *pos += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let arg = &tex[start..*pos];
                    *pos += 1;
                    return Some(arg);
                }
                *pos += 1;
            }
            _ => *pos += 1,
        }
    }
    None
}

/// Check that the next `count` color arguments (braced `{...}` groups, matching `pulldown-latex`'s
/// `lex::argument` requirement for `\color`/`\textcolor`/`\colorbox`/`\fcolorbox`) exist and
/// contain only ASCII bytes so `pulldown-latex`'s `lex::color` cannot slice mid-UTF-8 on `#...`
/// inputs.
fn color_args_non_ascii(tex: &str, mut pos: usize, count: usize) -> bool {
    let bytes = tex.as_bytes();
    for _ in 0..count {
        while pos < bytes.len() {
            if bytes[pos].is_ascii_whitespace() {
                pos += 1;
            } else if bytes[pos] == b'%' {
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
            } else {
                break;
            }
        }
        // Skip optional color model `[...]` (e.g. `\color[rgb]{...}`). Reject `%`, nested `[`,
        // `\`, braces, non-ASCII, or unclosed `[` immediately so commented `]`/`{...}` cannot
        // desync validation from `pulldown-latex`'s `lex::color`.
        if bytes.get(pos) == Some(&b'[') {
            pos += 1;
            let mut closed = false;
            while pos < bytes.len() {
                match bytes[pos] {
                    b']' => {
                        pos += 1;
                        closed = true;
                        break;
                    }
                    b'%' | b'[' | b'\\' | b'{' | b'}' => return true,
                    b if !b.is_ascii() => return true,
                    _ => pos += 1,
                }
            }
            if !closed {
                return true;
            }
        }
        let Some(arg) = next_braced_arg(tex, &mut pos) else {
            return true;
        };
        if !arg.is_ascii() {
            return true;
        }
    }
    false
}

/// How many required arguments `cmd` parses via `handle_argument` (and whether it also accepts a
/// leading optional `[...]` argument) in `pulldown-latex 0.8.0`.
fn recursive_primitive_arity(cmd: &str) -> (bool, u8) {
    match cmd {
        "sqrt" | "xleftarrow" | "xrightarrow" => (true, 1),
        "genfrac" => (false, 6),
        "sideset" | "fcolorbox" => (false, 3),
        "frac" | "cfrac" | "dfrac" | "tfrac" | "binom" | "dbinom" | "tbinom" | "overset"
        | "stackrel" | "underset" | "textcolor" | "colorbox" | "buildrel" => (false, 2),
        "pmod"
        | "not"
        | "cancel"
        | "acute"
        | "bar"
        | "overline"
        | "underbar"
        | "underline"
        | "breve"
        | "check"
        | "dot"
        | "ddot"
        | "grave"
        | "hat"
        | "tilde"
        | "vec"
        | "mathring"
        | "overleftarrow"
        | "underleftarrow"
        | "overrightarrow"
        | "Overrightarrow"
        | "underrightarrow"
        | "overleftrightarrow"
        | "underleftrightarrow"
        | "overleftharpoon"
        | "overrightharpoon"
        | "widecheck"
        | "widehat"
        | "widetilde"
        | "wideparen"
        | "overparen"
        | "overgroup"
        | "undergroup"
        | "overbrace"
        | "underbrace"
        | "underparen"
        | "overbracket"
        | "underbracket"
        | "mathbf"
        | "mathbfup"
        | "mathit"
        | "mathrm"
        | "mathup"
        | "mathsf"
        | "mathsfup"
        | "mathtt"
        | "mathbb"
        | "mathbbit"
        | "mathcal"
        | "mathbfcal"
        | "mathsfit"
        | "mathbfit"
        | "mathfrak"
        | "mathbffrak"
        | "mathbfsfup"
        | "mathbfsfit"
        | "mathscr"
        | "boldsymbol"
        | "bm"
        | "symbf"
        | "symbfup"
        | "symit"
        | "symup"
        | "symrm"
        | "symsf"
        | "symsfup"
        | "symtt"
        | "symbb"
        | "symbbit"
        | "symcal"
        | "symbfcal"
        | "symsfit"
        | "symbfit"
        | "symfrak"
        | "symbffrak"
        | "symbfsfup"
        | "symbfsfit"
        | "symscr"
        | "mathnormal"
        | "symnormal"
        | "mathbin"
        | "mathrel"
        | "mathop"
        | "mathord"
        | "mathopen"
        | "mathclose"
        | "mathpunct"
        | "mathinner"
        | "phantom"
        | "hphantom"
        | "vphantom"
        | "smash"
        | "boxed" => (false, 1),
        _ => (false, 0),
    }
}

/// Read-only lookahead for an optional `[...]` argument starting at `start` (after ASCII
/// whitespace), tracking nested `[`/`]` brackets identically to `pulldown-latex`'s
/// `lex::group_content(..., GroupingKind::OptionalArgument)`. Returns
/// `Some((end_after_bracket, is_empty_or_unclosed))` if `[` follows, without advancing the
/// caller's main scan cursor so every byte inside `[...]` is still scanned.
fn lookahead_optional_bracket(tex: &str, start: usize) -> Option<(usize, bool)> {
    let bytes = tex.as_bytes();
    let mut scan = start;
    while scan < bytes.len() && bytes[scan].is_ascii_whitespace() {
        scan += 1;
    }
    if bytes.get(scan) != Some(&b'[') {
        return None;
    }
    scan += 1;
    let body_start = scan;
    let mut bracket_depth = 0usize;
    while scan < bytes.len() {
        match bytes[scan] {
            b'\\' => {
                scan += 1;
                if scan < bytes.len() {
                    scan += tex[scan..].chars().next().map_or(1, char::len_utf8);
                }
            }
            b'%' => {
                // Treat comments inside `[...]` conservatively as non-braced/unbalanced.
                return Some((bytes.len(), true));
            }
            b'[' => {
                bracket_depth += 1;
                scan += 1;
            }
            b']' => {
                if bracket_depth == 0 {
                    let is_empty = tex[body_start..scan].trim().is_empty();
                    return Some((scan + 1, is_empty));
                }
                bracket_depth -= 1;
                scan += 1;
            }
            _ => {
                scan += tex[scan..].chars().next().map_or(1, char::len_utf8);
            }
        }
    }
    Some((scan, true))
}

/// Whether `ch` is a non-special literal character token parsed as a leaf by `pulldown-latex`'s
/// `handle_char_token` with zero call-stack recursion.
fn is_non_recursive_leaf_char(ch: char) -> bool {
    !matches!(
        ch,
        '\\' | '%' | '{' | '}' | '[' | ']' | '^' | '_' | '$' | '#' | '&' | '\'' | '~'
    )
}

/// Read-only lookahead checking whether all `arity` required arguments after `start` (and after
/// any optional `[...]` argument when `has_opt_bracket` is `true`) are non-recursive in
/// `pulldown-latex 0.8.0` — either braced `{...}` groups (which push an iterative
/// `Instruction::SubGroup` with zero call-stack recursion) or single literal non-special character
/// leaves (handled by `handle_char_token` without recursing into `handle_primitive`).
///
/// Returns `(all_non_recursive, empty_optional_bracket, opt_bracket_end)`.
fn inspect_primitive_args(
    tex: &str,
    start: usize,
    has_opt_bracket: bool,
    arity: u8,
) -> (bool, bool, Option<usize>) {
    let bytes = tex.as_bytes();
    let mut scan = start;
    let mut empty_opt_bracket = false;
    let mut opt_bracket_end = None;
    if has_opt_bracket
        && let Some((after_bracket, is_empty)) = lookahead_optional_bracket(tex, scan)
    {
        empty_opt_bracket = is_empty;
        opt_bracket_end = Some(after_bracket);
        if after_bracket >= bytes.len() {
            return (false, empty_opt_bracket, opt_bracket_end);
        }
        scan = after_bracket;
    }
    for _ in 0..arity {
        while scan < bytes.len() && bytes[scan].is_ascii_whitespace() {
            scan += 1;
        }
        let Some(&next) = bytes.get(scan) else {
            return (false, empty_opt_bracket, opt_bracket_end);
        };
        if next == b'{' {
            scan += 1;
            let mut depth = 1usize;
            while scan < bytes.len() && depth > 0 {
                match bytes[scan] {
                    b'\\' => {
                        scan += 1;
                        if scan < bytes.len() {
                            scan += tex[scan..].chars().next().map_or(1, char::len_utf8);
                        }
                    }
                    b'%' => return (false, empty_opt_bracket, opt_bracket_end),
                    b'{' => {
                        depth += 1;
                        scan += 1;
                    }
                    b'}' => {
                        depth -= 1;
                        scan += 1;
                    }
                    _ => {
                        scan += tex[scan..].chars().next().map_or(1, char::len_utf8);
                    }
                }
            }
            if depth != 0 {
                return (false, empty_opt_bracket, opt_bracket_end);
            }
        } else if let Some(ch) = tex[scan..].chars().next()
            && is_non_recursive_leaf_char(ch)
        {
            scan += ch.len_utf8();
        } else {
            return (false, empty_opt_bracket, opt_bracket_end);
        }
    }
    (true, empty_opt_bracket, opt_bracket_end)
}

/// Reject TeX inputs that are oversized or trigger known `pulldown-latex 0.8.0` panics,
/// macro-expansion OOMs, or stack-overflow recursions on `wasm32`.
pub(super) fn exceeds_tex_preflight(tex: &str) -> bool {
    if tex.len() > MATH_INPUT_MAX {
        return true;
    }
    // `pulldown-latex`'s `one_optional_space` slices `&input[1..]` on any `char::is_whitespace()`,
    // panicking on multi-byte Unicode whitespace such as U+00A0 or U+2003.
    if tex
        .chars()
        .any(|c| c.is_whitespace() && !c.is_ascii_whitespace())
    {
        return true;
    }
    let bytes = tex.as_bytes();
    let mut i = 0;
    let mut directives = 0usize;
    let mut comments = 0usize;
    let mut empty_groups = 0usize;
    let mut total_groups = 0usize;
    let mut brace_depth = 0usize;
    let mut unbraced_recursive = 0usize;
    let mut sqrt_opt_ends: Vec<usize> = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                comments += 1;
                if comments > MATH_COMMENTS_MAX {
                    return true;
                }
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => {
                total_groups += 1;
                if total_groups > MATH_GROUPS_MAX {
                    return true;
                }
                brace_depth += 1;
                if brace_depth > MATH_BRACE_DEPTH_MAX {
                    return true;
                }
                // Count empty `{}` / `{   }` groups (draining many empty SubGroups recurses in
                // `Parser::next()`).
                let mut look = i + 1;
                while look < bytes.len() && bytes[look].is_ascii_whitespace() {
                    look += 1;
                }
                if bytes.get(look) == Some(&b'}') {
                    empty_groups += 1;
                    if empty_groups > MATH_EMPTY_GROUPS_MAX {
                        return true;
                    }
                }
                i += 1;
            }
            b'}' => {
                brace_depth = brace_depth.saturating_sub(1);
                i += 1;
            }
            b if b.is_ascii_whitespace() => {
                i += 1;
            }
            b'\\' => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                    i += 1;
                }
                if i == start {
                    // Single non-letter control symbol (e.g. `\\`, `\%`, `\ `).
                    if i < bytes.len() {
                        i += tex[i..].chars().next().map_or(1, char::len_utf8);
                    }
                    continue;
                }
                let cmd = &tex[start..i];
                // Reject macro definitions (prevents 1 GiB two-`\def` OOM and `\newcommand[0][x]`
                // subtraction underflow) and `\char` (prevents `unsigned_integer` UTF-8 panic).
                if matches!(
                    cmd,
                    "def"
                        | "gdef"
                        | "edef"
                        | "xdef"
                        | "let"
                        | "futurelet"
                        | "newcommand"
                        | "renewcommand"
                        | "providecommand"
                        | "DeclareMathOperator"
                        | "char"
                ) {
                    return true;
                }
                if matches!(cmd, "color" | "textcolor" | "colorbox") {
                    if color_args_non_ascii(tex, i, 1) {
                        return true;
                    }
                } else if cmd == "fcolorbox" {
                    if color_args_non_ascii(tex, i, 2) {
                        return true;
                    }
                } else if cmd == "begin" {
                    let mut lookahead = i;
                    let Some(env_name) = next_braced_arg(tex, &mut lookahead) else {
                        return true;
                    };
                    // Reject `%` inside `\begin{...}` so `\begin{alignat%\n}{é}` cannot evade
                    // `alignat` count validation.
                    if env_name.contains('%') {
                        return true;
                    }
                    if matches!(env_name.trim(), "alignat" | "alignat*" | "alignedat") {
                        // `alignat` passes its count argument to `lex::unsigned_integer`, which
                        // panics on non-ASCII bytes or overflows on huge integers.
                        let Some(count_arg) = next_braced_arg(tex, &mut lookahead) else {
                            return true;
                        };
                        let count = count_arg.trim();
                        if count.is_empty()
                            || count.len() > 3
                            || !count.bytes().all(|b| b.is_ascii_digit())
                        {
                            return true;
                        }
                    }
                } else if matches!(
                    cmd,
                    "relax"
                        | "global"
                        | "long"
                        | "outer"
                        | "protected"
                        | "expandafter"
                        | "noexpand"
                        | "csname"
                        | "ignorespaces"
                        | "mathchardef"
                        | "chardef"
                ) {
                    directives += 1;
                    if directives > MATH_DIRECTIVES_MAX {
                        return true;
                    }
                }

                // Monotonically cap recursive primitive invocations whose arguments are not all
                // braced groups or single literal leaves (plus every `\buildrel`), and bound
                // nested `\sqrt[...]` optional indices (which stack bare `SubGroup`s without
                // trailing `Event::End` in `pulldown-latex`).
                let (has_opt_bracket, arity) = recursive_primitive_arity(cmd);
                if arity > 0 {
                    if cmd == "buildrel" {
                        unbraced_recursive += 1;
                    } else {
                        let (all_non_recursive, empty_opt, opt_end) =
                            inspect_primitive_args(tex, i, has_opt_bracket, arity);
                        if cmd == "sqrt"
                            && let Some(end) = opt_end
                        {
                            while sqrt_opt_ends.last().is_some_and(|&prev_end| prev_end <= i) {
                                sqrt_opt_ends.pop();
                            }
                            sqrt_opt_ends.push(end);
                            if sqrt_opt_ends.len() > MATH_CONSECUTIVE_CS_MAX {
                                return true;
                            }
                        }
                        if empty_opt {
                            empty_groups += 1;
                            if empty_groups > MATH_EMPTY_GROUPS_MAX {
                                return true;
                            }
                        }
                        if !all_non_recursive {
                            unbraced_recursive += 1;
                        }
                    }
                    if unbraced_recursive > MATH_CONSECUTIVE_CS_MAX {
                        return true;
                    }
                }
            }
            _ => {
                i += tex[i..].chars().next().map_or(1, char::len_utf8);
            }
        }
    }
    false
}
