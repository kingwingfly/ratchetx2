use std::fmt::Write as _;

use pulldown_latex::{
    Storage,
    config::DisplayMode,
    event::{
        ArrayColumn, ColorChange, ColorTarget, ColumnAlignment, Content, DelimiterSize,
        DelimiterType, Dimension, DimensionUnit, EnvironmentFlow, Event as LatexEvent, Font,
        Grouping, Line, ScriptPosition, ScriptType, StateChange, Style, Visual,
    },
};

use super::sanitize::{escape, math_dimension_unit_max, push_escaped_char, push_escaped_text};

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
/// Maximum `pulldown-latex` events rendered in a single expression before falling back to raw TeX.
const MATH_EVENTS_MAX: usize = 20_000;
/// Maximum MathML group/script/visual nesting depth before falling back to raw TeX.
const MATH_DEPTH_MAX: usize = 128;
/// Maximum columns/separators allowed in an `\begin{array}{...}` specification.
const MATH_ARRAY_COLS_MAX: usize = 128;
/// Maximum consecutive horizontal lines (`\hline` / `\hdashline`) emitted at one row boundary.
const MATH_HLINES_MAX: usize = 32;
/// Maximum output bytes for a single MathML expression before falling back to raw TeX.
const MATH_HTML_MAX: usize = 256 * 1024;

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
fn exceeds_tex_preflight(tex: &str) -> bool {
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

/// The TeX `tex` as CSP-safe, HTML-escaped MathML, or HTML-escaped raw TeX on any parser or
/// rendering error.
pub(super) fn mathml(tex: &str, display_mode: DisplayMode) -> String {
    if exceeds_tex_preflight(tex) {
        return escape(tex);
    }
    let storage = Storage::new();
    let parser = pulldown_latex::Parser::new(tex, &storage);
    let mut events = Vec::new();
    for event in parser {
        let Ok(event) = event else {
            return escape(tex);
        };
        if events.len() >= MATH_EVENTS_MAX {
            return escape(tex);
        }
        events.push(event);
    }
    match MathmlRenderer::new(&events, display_mode).render() {
        Ok(rendered) => rendered,
        Err(()) => escape(tex),
    }
}

/// Strict HTML-escaping, zero-inline-style MathML renderer walking `pulldown-latex` events
/// directly.
pub(super) struct MathmlRenderer<'a> {
    events: &'a [LatexEvent<'a>],
    cursor: usize,
    display_mode: DisplayMode,
    out: String,
    env_stack: Vec<MathEnv>,
    state_stack: Vec<MathState>,
    previous_atom: Option<MathAtom>,
}

#[derive(Clone, Copy)]
enum MathAtom {
    Bin,
    Op,
    Rel,
    Open,
    Close,
    Punct,
    Ord,
    Inner,
}

#[derive(Debug, Clone, PartialEq)]
enum MathEnvGrouping {
    Normal,
    LeftRight {
        closing: Option<char>,
    },
    Array {
        cols: Box<[ArrayColumn]>,
        cols_index: usize,
    },
    Matrix,
    Cases {
        used_align: bool,
        left: bool,
    },
    Align,
    Alignat {
        pairs: u16,
        columns_used: u16,
    },
    SubArray,
    Gather,
    Multline,
    Split {
        used_align: bool,
    },
    Equation,
}

#[derive(Debug, Clone, PartialEq)]
enum MathEnv {
    Group(MathEnvGrouping),
    Visual {
        ty: Visual,
        count: u8,
    },
    Script {
        ty: ScriptType,
        above_below: bool,
        count: u8,
        fn_application: bool,
    },
}

#[derive(Debug, Clone, Copy, Default)]
struct MathState {
    font: Option<Font>,
    border: bool,
    style: Option<Style>,
}

impl<'a> MathmlRenderer<'a> {
    pub(super) fn new(events: &'a [LatexEvent<'a>], display_mode: DisplayMode) -> Self {
        Self {
            events,
            cursor: 0,
            display_mode,
            out: String::new(),
            env_stack: Vec::with_capacity(16),
            state_stack: vec![MathState::default()],
            previous_atom: None,
        }
    }

    fn state(&self) -> MathState {
        self.state_stack.last().copied().unwrap_or_default()
    }

    fn check_bounds(&self) -> Result<(), ()> {
        if self.out.len() > MATH_HTML_MAX || self.env_stack.len() > MATH_DEPTH_MAX {
            Err(())
        } else {
            Ok(())
        }
    }

    fn peek(&self) -> Option<&'a LatexEvent<'a>> {
        self.events.get(self.cursor)
    }

    fn next_event(&mut self) -> Option<&'a LatexEvent<'a>> {
        let event = self.events.get(self.cursor)?;
        self.cursor += 1;
        Some(event)
    }

    fn open_tag(&mut self, tag: &'static str, classes: Option<&'static str>) {
        let state = self.state();
        self.out.push('<');
        self.out.push_str(tag);
        if let Some(style) = state.style
            && !matches!(
                self.env_stack.last(),
                Some(
                    MathEnv::Script {
                        ty: ScriptType::Subscript | ScriptType::Superscript,
                        count: 0,
                        ..
                    } | MathEnv::Script {
                        ty: ScriptType::SubSuperscript,
                        count: 0 | 1,
                        ..
                    }
                )
            )
        {
            let (displaystyle, scriptlevel) = match style {
                Style::Display => ("true", "0"),
                Style::Text => ("false", "0"),
                Style::Script => ("false", "1"),
                Style::ScriptScript => ("false", "2"),
            };
            let _ = write!(
                self.out,
                " displaystyle=\"{displaystyle}\" scriptlevel=\"{scriptlevel}\""
            );
        }
        match (classes, state.border) {
            (Some(cls), true) => {
                let _ = write!(self.out, " class=\"{cls} ml-box\"");
            }
            (Some(cls), false) => {
                let _ = write!(self.out, " class=\"{cls}\"");
            }
            (None, true) => self.out.push_str(" class=\"ml-box\""),
            (None, false) => {}
        }
    }

    pub(super) fn render(mut self) -> Result<String, ()> {
        let mode = match self.display_mode {
            DisplayMode::Inline => "inline",
            DisplayMode::Block => "block",
        };
        let _ = write!(self.out, "<math display=\"{mode}\">");

        while let Some(event) = self.next_event() {
            self.write_event(event)?;
            self.check_bounds()?;

            while let Some((tag, count, fn_application)) =
                self.env_stack.last_mut().and_then(|env| match env {
                    MathEnv::Group(_) => None,
                    MathEnv::Visual { ty, count } => Some((visual_tag(*ty), count, None)),
                    MathEnv::Script {
                        ty,
                        above_below,
                        count,
                        fn_application,
                    } => Some((script_tag(*ty, *above_below), count, Some(*fn_application))),
                })
            {
                if *count != 0 {
                    *count -= 1;
                    break;
                }
                self.out.push_str("</");
                self.out.push_str(tag);
                self.out.push('>');
                self.set_previous_atom(MathAtom::Inner);
                self.env_stack.pop();

                if fn_application.unwrap_or(false)
                    && let Some(atom) = self.next_atom()
                {
                    self.out.push_str("<mo>\u{2061}</mo>");
                    if !matches!(atom, MathAtom::Open | MathAtom::Punct | MathAtom::Close) {
                        self.out.push_str("<mspace width=\"0.1667em\" />");
                    }
                }
            }
            self.check_bounds()?;
        }

        if !self.env_stack.is_empty() || self.state_stack.len() != 1 {
            return Err(());
        }
        self.out.push_str("</math>");
        Ok(self.out)
    }

    fn begin_mtable(
        &mut self,
        class: Option<&str>,
        with_eqn: bool,
        start_lines: bool,
        open_cell: bool,
    ) -> Result<(), ()> {
        self.out.push_str("<mtable");
        match (class, with_eqn) {
            (Some(cls), true) => {
                let _ = write!(self.out, " class=\"{cls} ml-with-eqn\"");
            }
            (Some(cls), false) => {
                let _ = write!(self.out, " class=\"{cls}\"");
            }
            (None, true) => self.out.push_str(" class=\"ml-with-eqn\""),
            (None, false) => {}
        }
        self.out.push_str("><mtr");
        if start_lines
            && let Some(LatexEvent::EnvironmentFlow(EnvironmentFlow::StartLines { lines })) =
                self.events.get(self.cursor)
        {
            write_env_horizontal_lines(&mut self.out, lines)?;
            self.cursor += 1;
        }
        if open_cell {
            self.out.push_str("><mtd>");
        } else {
            self.out.push('>');
        }
        Ok(())
    }

    fn write_event(&mut self, event: &'a LatexEvent<'a>) -> Result<(), ()> {
        match event {
            LatexEvent::Content(content) => self.write_content(*content, false),
            LatexEvent::Begin(grouping) => {
                self.previous_atom = None;
                let math_env = !matches!(grouping, Grouping::Normal | Grouping::LeftRight(_, _));
                if math_env {
                    self.state_stack.push(MathState::default());
                } else {
                    let last_state = self.state();
                    self.state_stack.push(last_state);
                    while let Some(LatexEvent::StateChange(state_change)) = self.peek() {
                        let state_change = *state_change;
                        self.handle_state_change(state_change);
                        self.next_event();
                    }
                    self.open_tag("mrow", None);
                    self.out.push('>');
                    if let Some(top) = self.state_stack.last_mut() {
                        *top = MathState {
                            font: top.font,
                            ..MathState::default()
                        };
                    }
                }

                let env_group = match grouping {
                    Grouping::Normal => MathEnvGrouping::Normal,
                    Grouping::LeftRight(opening, closing) => {
                        if let Some(delim) = *opening {
                            self.open_tag("mo", None);
                            self.out.push_str(" stretchy=\"true\">");
                            push_escaped_char(&mut self.out, delim);
                            self.out.push_str("</mo>");
                        }
                        self.previous_atom = Some(MathAtom::Open);
                        MathEnvGrouping::LeftRight { closing: *closing }
                    }
                    Grouping::Align { eq_numbers } => {
                        self.begin_mtable(Some("ml-alignlike ml-align"), *eq_numbers, true, true)?;
                        MathEnvGrouping::Align
                    }
                    Grouping::Matrix { alignment } => {
                        let cls = match alignment {
                            ColumnAlignment::Left => "ml-arraylike ml-cells-left",
                            ColumnAlignment::Center => "ml-arraylike",
                            ColumnAlignment::Right => "ml-arraylike ml-cells-right",
                        };
                        self.begin_mtable(Some(cls), false, true, true)?;
                        MathEnvGrouping::Matrix
                    }
                    Grouping::Cases { left } => {
                        self.out.push_str("<mrow>");
                        if *left {
                            self.out.push_str("<mo stretchy=\"true\">{</mo>");
                        }
                        self.begin_mtable(Some("ml-cells-left ml-cases"), false, true, true)?;
                        MathEnvGrouping::Cases {
                            left: *left,
                            used_align: false,
                        }
                    }
                    Grouping::Array(cols) => {
                        if cols.len() > MATH_ARRAY_COLS_MAX {
                            return Err(());
                        }
                        self.begin_mtable(Some("ml-arraylike"), false, true, false)?;
                        let index = array_newline(&mut self.out, cols)?;
                        MathEnvGrouping::Array {
                            cols: cols.clone(),
                            cols_index: index,
                        }
                    }
                    Grouping::Aligned => {
                        self.begin_mtable(Some("ml-alignlike ml-align"), false, true, true)?;
                        MathEnvGrouping::Align
                    }
                    Grouping::SubArray { alignment } => {
                        let cls = match alignment {
                            ColumnAlignment::Left => Some("ml-cells-left"),
                            ColumnAlignment::Center => None,
                            ColumnAlignment::Right => Some("ml-cells-right"),
                        };
                        self.begin_mtable(cls, false, true, true)?;
                        MathEnvGrouping::SubArray
                    }
                    Grouping::Alignat { pairs, eq_numbers } => {
                        self.begin_mtable(Some("ml-alignlike"), *eq_numbers, true, true)?;
                        MathEnvGrouping::Alignat {
                            pairs: *pairs,
                            columns_used: 0,
                        }
                    }
                    Grouping::Alignedat { pairs } => {
                        self.begin_mtable(Some("ml-alignlike"), false, true, true)?;
                        MathEnvGrouping::Alignat {
                            pairs: *pairs,
                            columns_used: 0,
                        }
                    }
                    Grouping::Gather { eq_numbers } => {
                        self.begin_mtable(None, *eq_numbers, true, true)?;
                        MathEnvGrouping::Gather
                    }
                    Grouping::Gathered => {
                        self.begin_mtable(None, false, true, true)?;
                        MathEnvGrouping::Gather
                    }
                    Grouping::Multline => {
                        self.begin_mtable(Some("ml-multline"), false, true, true)?;
                        MathEnvGrouping::Multline
                    }
                    Grouping::Split => {
                        self.begin_mtable(Some("ml-alignlike"), false, true, true)?;
                        MathEnvGrouping::Split { used_align: false }
                    }
                    Grouping::Equation { eq_numbers } => {
                        self.begin_mtable(None, *eq_numbers, false, true)?;
                        MathEnvGrouping::Equation
                    }
                };
                self.env_stack.push(MathEnv::Group(env_group));
                Ok(())
            }
            LatexEvent::End => {
                let Some(MathEnv::Group(grouping)) = self.env_stack.pop() else {
                    return Err(());
                };
                if self.state_stack.len() <= 1 {
                    return Err(());
                }
                self.state_stack.pop();
                self.previous_atom = Some(MathAtom::Inner);
                match grouping {
                    MathEnvGrouping::Normal => self.out.push_str("</mrow>"),
                    MathEnvGrouping::LeftRight { closing } => {
                        if let Some(delim) = closing {
                            self.open_tag("mo", None);
                            self.out.push_str(" stretchy=\"true\">");
                            push_escaped_char(&mut self.out, delim);
                            self.out.push_str("</mo>");
                        }
                        self.previous_atom = Some(MathAtom::Close);
                        self.out.push_str("</mrow>");
                    }
                    MathEnvGrouping::Matrix
                    | MathEnvGrouping::Align
                    | MathEnvGrouping::SubArray
                    | MathEnvGrouping::Gather
                    | MathEnvGrouping::Multline
                    | MathEnvGrouping::Equation
                    | MathEnvGrouping::Split { .. }
                    | MathEnvGrouping::Alignat { .. } => {
                        self.out.push_str("</mtd></mtr></mtable>");
                    }
                    MathEnvGrouping::Array { cols, cols_index } => {
                        self.out.push_str("</mtd>");
                        if let Some(rest) = cols.get(cols_index..) {
                            for col in rest {
                                match col {
                                    ArrayColumn::Separator(Line::Solid) => {
                                        self.out.push_str(
                                            "<mtd class=\"ml-right-solid ml-border-only\"></mtd>",
                                        );
                                    }
                                    ArrayColumn::Separator(Line::Dashed) => {
                                        self.out.push_str(
                                            "<mtd class=\"ml-right-dashed ml-border-only\"></mtd>",
                                        );
                                    }
                                    ArrayColumn::Column(_) => break,
                                }
                            }
                        }
                        self.out.push_str("</mtr></mtable>");
                    }
                    MathEnvGrouping::Cases { left, .. } => {
                        self.out.push_str("</mtd></mtr></mtable>");
                        if !left {
                            self.out.push_str("<mo stretchy=\"true\">}</mo>");
                        }
                        self.out.push_str("</mrow>");
                    }
                }
                Ok(())
            }
            LatexEvent::Visual(visual) => {
                let visual = *visual;
                if visual == Visual::Negation {
                    if let Some(LatexEvent::Content(
                        content @ (Content::Ordinary { .. }
                        | Content::Relation { .. }
                        | Content::BinaryOp { .. }
                        | Content::LargeOp { .. }
                        | Content::Delimiter { .. }
                        | Content::Punctuation(_)),
                    )) = self.peek()
                    {
                        let content = *content;
                        self.next_event();
                        return self.write_content(content, true);
                    }
                    self.open_tag("mrow", Some("ml-negated"));
                    self.out.push('>');
                    self.env_stack.push(MathEnv::Visual {
                        ty: visual,
                        count: 1,
                    });
                    return Ok(());
                }
                let count = match visual {
                    Visual::SquareRoot | Visual::Negation => 1,
                    Visual::Root | Visual::Fraction(_) => 2,
                };
                self.env_stack.push(MathEnv::Visual { ty: visual, count });
                self.open_tag(visual_tag(visual), None);
                if let Visual::Fraction(Some(dim)) = visual
                    && let Some(thickness) = format_dimension(dim, false)
                {
                    let _ = write!(self.out, " linethickness=\"{thickness}\"");
                }
                self.out.push('>');
                Ok(())
            }
            LatexEvent::Script { ty, position } => {
                let state = self.state();
                let above_below = match position {
                    ScriptPosition::Right => false,
                    ScriptPosition::AboveBelow => true,
                    ScriptPosition::Movable => {
                        state.style == Some(Style::Display)
                            || (state.style.is_none() && self.display_mode == DisplayMode::Block)
                    }
                };
                let count = match ty {
                    ScriptType::Subscript | ScriptType::Superscript => 2,
                    ScriptType::SubSuperscript => 3,
                };
                self.env_stack.push(MathEnv::Script {
                    ty: *ty,
                    above_below,
                    count,
                    fn_application: false,
                });
                self.open_tag(script_tag(*ty, above_below), None);
                self.out.push('>');
                Ok(())
            }
            LatexEvent::Space {
                width,
                height,
                depth,
            } => {
                self.out.push_str("<mspace");
                if let Some(width) = width.and_then(|d| format_dimension(d, true)) {
                    let _ = write!(self.out, " width=\"{width}\"");
                }
                if let Some(height) = height.and_then(|d| format_dimension(d, false)) {
                    let _ = write!(self.out, " height=\"{height}\"");
                }
                if let Some(depth) = depth.and_then(|d| format_dimension(d, false)) {
                    let _ = write!(self.out, " depth=\"{depth}\"");
                }
                self.out.push_str(" />");
                Ok(())
            }
            LatexEvent::StateChange(state_change) => {
                self.handle_state_change(*state_change);
                Ok(())
            }
            LatexEvent::EnvironmentFlow(EnvironmentFlow::NewLine {
                spacing,
                horizontal_lines,
            }) => {
                if let Some(top) = self.state_stack.last_mut() {
                    *top = MathState::default();
                }
                self.previous_atom = None;

                if let Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) =
                    self.env_stack.last()
                {
                    let rest = cols.get(*cols_index..).unwrap_or(&[]);
                    array_close_line(&mut self.out, rest)?;
                } else if let Some(MathEnv::Group(MathEnvGrouping::Equation)) =
                    self.env_stack.last()
                {
                    return Ok(());
                } else if matches!(self.env_stack.last(), Some(MathEnv::Group(_))) {
                    self.out.push_str("</mtd></mtr><mtr");
                } else {
                    return Err(());
                }

                if let Some(spacing) = *spacing {
                    self.out.push('>');
                    if let Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) =
                        self.env_stack.last_mut()
                    {
                        let mut index = array_newline(&mut self.out, cols)?;
                        if let Some(height) = format_dimension(spacing, false)
                            && spacing.value > 0.0
                        {
                            let _ = write!(self.out, "<mspace height=\"{height}\" />");
                        }
                        while index < *cols_index {
                            array_align(&mut self.out, cols, &mut index)?;
                        }
                        let rest = cols.get(index..).unwrap_or(&[]);
                        array_close_line(&mut self.out, rest)?;
                    } else {
                        self.out.push_str("<mtd class=\"ml-nonumber\">");
                        if let Some(height) = format_dimension(spacing, false)
                            && spacing.value > 0.0
                        {
                            let _ = write!(self.out, "<mspace height=\"{height}\" />");
                        }
                        self.out.push_str("</mtd></mtr><mtr");
                    }
                }
                write_env_horizontal_lines(&mut self.out, horizontal_lines)?;

                match self.env_stack.last_mut() {
                    Some(MathEnv::Group(
                        MathEnvGrouping::Cases { used_align, .. }
                        | MathEnvGrouping::Split { used_align },
                    )) => {
                        *used_align = false;
                        self.out.push_str("><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(
                        MathEnvGrouping::Matrix
                        | MathEnvGrouping::Align
                        | MathEnvGrouping::Gather
                        | MathEnvGrouping::SubArray
                        | MathEnvGrouping::Multline,
                    )) => {
                        self.out.push_str("><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) => {
                        self.out.push('>');
                        let new_index = array_newline(&mut self.out, cols)?;
                        *cols_index = new_index;
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Alignat { columns_used, .. })) => {
                        *columns_used = 0;
                        self.out.push_str("><mtd>");
                        Ok(())
                    }
                    _ => Err(()),
                }
            }
            LatexEvent::EnvironmentFlow(EnvironmentFlow::Alignment) => {
                if let Some(top) = self.state_stack.last_mut() {
                    *top = MathState::default();
                }
                self.previous_atom = None;
                match self.env_stack.last_mut() {
                    Some(MathEnv::Group(
                        MathEnvGrouping::Cases { used_align, .. }
                        | MathEnvGrouping::Split { used_align },
                    )) if !*used_align => {
                        *used_align = true;
                        self.out.push_str("</mtd><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Align | MathEnvGrouping::Matrix)) => {
                        self.out.push_str("</mtd><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Alignat {
                        pairs,
                        columns_used,
                    })) if u32::from(*columns_used) + 1 < u32::from(*pairs) * 2 => {
                        *columns_used += 1;
                        self.out.push_str("</mtd><mtd>");
                        Ok(())
                    }
                    Some(MathEnv::Group(MathEnvGrouping::Array { cols, cols_index })) => {
                        array_align(&mut self.out, cols, cols_index)
                    }
                    _ => Err(()),
                }
            }
            LatexEvent::EnvironmentFlow(EnvironmentFlow::StartLines { .. }) => Err(()),
        }
    }

    fn write_content(&mut self, content: Content<'a>, negate: bool) -> Result<(), ()> {
        match content {
            Content::Text(text) => {
                self.open_tag("mtext", None);
                self.out.push('>');
                if text == "&nbsp;" {
                    self.out.push('\u{00A0}');
                } else {
                    let trimmed = text.trim();
                    if text.starts_with(char::is_whitespace) {
                        self.out.push('\u{00A0}');
                    }
                    match self.state().font {
                        None => push_escaped_text(&mut self.out, trimmed),
                        Some(font) => {
                            for c in trimmed.chars() {
                                push_escaped_char(&mut self.out, map_font_char(font, c));
                            }
                        }
                    }
                    if !trimmed.is_empty() && text.ends_with(char::is_whitespace) {
                        self.out.push('\u{00A0}');
                    }
                }
                self.set_previous_atom(MathAtom::Ord);
                self.out.push_str("</mtext>");
            }
            Content::Number(number) => {
                self.open_tag("mn", None);
                self.out.push('>');
                let font = match self.state().font {
                    Some(Font::BoldSymbol) => Some(Font::Bold),
                    other => other,
                };
                for c in number.chars() {
                    let mapped = font.map_or(c, |f| map_font_char(f, c));
                    push_escaped_char(&mut self.out, mapped);
                }
                self.set_previous_atom(MathAtom::Ord);
                self.out.push_str("</mn>");
            }
            Content::Function(name) => {
                if matches!(
                    self.previous_atom,
                    Some(MathAtom::Inner | MathAtom::Close | MathAtom::Ord)
                ) {
                    self.out.push_str("<mspace width=\"0.1667em\" />");
                }
                self.open_tag("mi", None);
                if name.chars().count() == 1 {
                    self.out.push_str(" mathvariant=\"normal\">");
                } else {
                    self.out.push('>');
                }
                // Always HTML-escape operator/function names (e.g. \operatorname{...}, \mathop{...}).
                push_escaped_text(&mut self.out, name);
                self.set_previous_atom(MathAtom::Op);
                self.out.push_str("</mi>");

                if let Some(MathEnv::Script { fn_application, .. }) = self.env_stack.last_mut() {
                    *fn_application = true;
                } else if let Some(atom) = self.next_atom() {
                    self.out.push_str("<mo>\u{2061}</mo>");
                    if !matches!(atom, MathAtom::Open | MathAtom::Punct | MathAtom::Close) {
                        self.out.push_str("<mspace width=\"0.1667em\" />");
                    }
                }
            }
            Content::Ordinary { content, stretchy } => {
                if stretchy {
                    self.open_tag("mo", None);
                    self.out.push_str(" stretchy=\"true\">");
                    push_escaped_char(&mut self.out, content);
                    if negate {
                        self.out.push('\u{0338}');
                    }
                    self.set_previous_atom(MathAtom::Ord);
                    self.out.push_str("</mo>");
                } else {
                    self.open_tag("mi", None);
                    // TeX math style: uppercase Greek letters are upright by default.
                    let should_be_upright = content.is_uppercase() && !content.is_ascii_uppercase();
                    let mapped = match (self.state().font, should_be_upright) {
                        (Some(Font::UpRight), _) | (None, true) => {
                            self.out.push_str(" mathvariant=\"normal\">");
                            content
                        }
                        (Some(font), upright) => {
                            self.out.push('>');
                            let font = if font == Font::BoldSymbol {
                                if upright {
                                    Font::Bold
                                } else {
                                    Font::BoldItalic
                                }
                            } else {
                                font
                            };
                            map_font_char(font, content)
                        }
                        _ => {
                            self.out.push('>');
                            content
                        }
                    };
                    push_escaped_char(&mut self.out, mapped);
                    if negate {
                        self.out.push('\u{0338}');
                    }
                    self.set_previous_atom(MathAtom::Ord);
                    self.out.push_str("</mi>");
                }
            }
            Content::BinaryOp { content, small } => {
                let tag = if matches!(
                    self.previous_atom,
                    Some(MathAtom::Inner | MathAtom::Close | MathAtom::Ord)
                ) && !matches!(
                    self.env_stack.last(),
                    Some(
                        MathEnv::Script { .. }
                            | MathEnv::Visual {
                                ty: Visual::Root | Visual::Fraction(_) | Visual::SquareRoot,
                                ..
                            }
                    )
                ) && matches!(
                    self.next_atom(),
                    Some(
                        MathAtom::Inner
                            | MathAtom::Bin
                            | MathAtom::Op
                            | MathAtom::Ord
                            | MathAtom::Open
                    )
                ) {
                    self.set_previous_atom(MathAtom::Bin);
                    "mo"
                } else {
                    self.set_previous_atom(MathAtom::Ord);
                    "mi"
                };

                self.open_tag(tag, small.then_some("ml-small"));
                self.out.push('>');
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.out.push_str("</");
                self.out.push_str(tag);
                self.out.push('>');
            }
            Content::Relation { content, small } => {
                let mut buf = [0u8; 8];
                let slice = content.encode_utf8_to_buf(&mut buf);
                let text = std::str::from_utf8(slice).map_err(|_| ())?;
                self.open_tag("mo", small.then_some("ml-small"));
                self.out.push('>');
                push_escaped_text(&mut self.out, text);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(MathAtom::Rel);
                self.out.push_str("</mo>");
            }
            Content::LargeOp { content, small } => {
                self.open_tag("mo", None);
                if small {
                    self.out.push_str(" largeop=\"false\"");
                }
                self.out.push_str(" movablelimits=\"false\">");
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(MathAtom::Op);
                self.out.push_str("</mo>");
            }
            Content::Delimiter { content, size, ty } => {
                self.open_tag("mo", None);
                let stretch = ty == DelimiterType::Fence || size.is_some();
                let _ = write!(self.out, " symmetric=\"{stretch}\" stretchy=\"{stretch}\"");
                if let Some(size) = size {
                    let em = match size {
                        DelimiterSize::Big => "1.2",
                        DelimiterSize::BIG => "1.8",
                        DelimiterSize::Bigg => "2.4",
                        DelimiterSize::BIGG => "3",
                    };
                    let _ = write!(self.out, " minsize=\"{em}em\" maxsize=\"{em}em\"");
                }
                self.out.push('>');
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(match ty {
                    DelimiterType::Open => MathAtom::Open,
                    DelimiterType::Fence => MathAtom::Punct,
                    DelimiterType::Close => MathAtom::Close,
                });
                self.out.push_str("</mo>");
            }
            Content::Punctuation(content) => {
                self.open_tag("mo", None);
                self.out.push('>');
                push_escaped_char(&mut self.out, content);
                if negate {
                    self.out.push('\u{0338}');
                }
                self.set_previous_atom(MathAtom::Punct);
                self.out.push_str("</mo>");
            }
        }
        Ok(())
    }

    fn handle_state_change(&mut self, state_change: StateChange) {
        let Some(state) = self.state_stack.last_mut() else {
            return;
        };
        match state_change {
            StateChange::Font(font) => state.font = font,
            StateChange::Color(ColorChange { target, .. }) => {
                // Boxed borders use a CSS class allowed by the page's CSP.
                if target == ColorTarget::Border {
                    state.border = true;
                }
            }
            StateChange::Style(style) => state.style = Some(style),
        }
    }

    fn set_previous_atom(&mut self, atom: MathAtom) {
        if !matches!(
            self.env_stack.last(),
            Some(
                MathEnv::Visual {
                    ty: Visual::Root | Visual::Fraction(_),
                    count: 0,
                } | MathEnv::Script {
                    ty: ScriptType::Subscript | ScriptType::Superscript,
                    count: 0,
                    ..
                } | MathEnv::Script {
                    ty: ScriptType::SubSuperscript,
                    count: 0 | 1,
                    ..
                }
            )
        ) {
            self.previous_atom = Some(atom);
        }
    }

    fn next_atom(&self) -> Option<MathAtom> {
        let mut idx = self.cursor;
        while let Some(next) = self.events.get(idx) {
            idx += 1;
            return match next {
                LatexEvent::StateChange(_)
                | LatexEvent::Space { .. }
                | LatexEvent::Visual(Visual::Negation)
                | LatexEvent::Script { .. } => continue,
                LatexEvent::End | LatexEvent::EnvironmentFlow(_) => None,
                LatexEvent::Visual(_) | LatexEvent::Begin(_) => Some(MathAtom::Inner),
                LatexEvent::Content(content) => match content {
                    Content::BinaryOp { .. } => Some(MathAtom::Bin),
                    Content::LargeOp { .. } => Some(MathAtom::Op),
                    Content::Relation { .. } => Some(MathAtom::Rel),
                    Content::Delimiter {
                        ty: DelimiterType::Open,
                        ..
                    } => Some(MathAtom::Open),
                    Content::Delimiter {
                        ty: DelimiterType::Close,
                        ..
                    } => Some(MathAtom::Close),
                    Content::Punctuation(_) => Some(MathAtom::Punct),
                    _ => Some(MathAtom::Ord),
                },
            };
        }
        None
    }
}

fn script_tag(ty: ScriptType, above_below: bool) -> &'static str {
    match (ty, above_below) {
        (ScriptType::Subscript, false) => "msub",
        (ScriptType::Superscript, false) => "msup",
        (ScriptType::SubSuperscript, false) => "msubsup",
        (ScriptType::Subscript, true) => "munder",
        (ScriptType::Superscript, true) => "mover",
        (ScriptType::SubSuperscript, true) => "munderover",
    }
}

fn visual_tag(visual: Visual) -> &'static str {
    match visual {
        Visual::Root => "mroot",
        Visual::Fraction(_) => "mfrac",
        Visual::SquareRoot => "msqrt",
        Visual::Negation => "mrow",
    }
}

fn format_dimension(dim: Dimension, allow_negative: bool) -> Option<String> {
    const BP_PER_PT: f64 = 72.0 / 72.27;
    const BP_PER_SP: f64 = (1.0 / 65536.0) * BP_PER_PT;
    const BP_PER_DD: f64 = (1238.0 / 1157.0) * BP_PER_PT;
    const BP_PER_CC: f64 = 12.0 * BP_PER_DD;
    const EM_PER_MU: f64 = 1.0 / 18.0;
    if !dim.value.is_finite() {
        return None;
    }
    let raw = f64::from(dim.value);
    let (value, unit) = match dim.unit {
        DimensionUnit::Em => (raw, "em"),
        DimensionUnit::Mu => (raw * EM_PER_MU, "em"),
        DimensionUnit::Ex => (raw, "ex"),
        DimensionUnit::Mm => (raw, "mm"),
        DimensionUnit::Cm => (raw, "cm"),
        DimensionUnit::In => (raw, "in"),
        DimensionUnit::Bp => (raw, "pt"),
        DimensionUnit::Pt => (raw * BP_PER_PT, "pt"),
        DimensionUnit::Pc => (raw * BP_PER_PT, "pc"),
        DimensionUnit::Sp => (raw * BP_PER_SP, "pt"),
        DimensionUnit::Dd => (raw * BP_PER_DD, "pt"),
        DimensionUnit::Cc => (raw * BP_PER_CC, "pt"),
    };
    if !value.is_finite() || (!allow_negative && value < 0.0) {
        return None;
    }
    let max = math_dimension_unit_max(unit)?;
    let clamped = if allow_negative {
        value.clamp(-max, max)
    } else {
        value.clamp(0.0, max)
    };
    let formatted = format!("{clamped:.4}");
    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
    let trimmed = if trimmed == "-0" || trimmed.is_empty() {
        "0"
    } else {
        trimmed
    };
    Some(format!("{trimmed}{unit}"))
}

fn push_array_cell_classes(
    out: &mut String,
    left: Option<Line>,
    align: ColumnAlignment,
    right: Option<Line>,
) {
    let mut classes = Vec::with_capacity(3);
    if let Some(line) = left {
        classes.push(match line {
            Line::Solid => "ml-left-solid",
            Line::Dashed => "ml-left-dashed",
        });
    }
    match align {
        ColumnAlignment::Left => classes.push("ml-cell-left"),
        ColumnAlignment::Center => {}
        ColumnAlignment::Right => classes.push("ml-cell-right"),
    }
    if let Some(line) = right {
        classes.push(match line {
            Line::Solid => "ml-right-solid",
            Line::Dashed => "ml-right-dashed",
        });
    }
    if !classes.is_empty() {
        let _ = write!(out, " class=\"{}\"", classes.join(" "));
    }
    out.push('>');
}

fn array_newline(out: &mut String, cols: &[ArrayColumn]) -> Result<usize, ()> {
    if cols.len() > MATH_ARRAY_COLS_MAX {
        return Err(());
    }
    let mut index = 0;
    out.push_str("<mtd");
    for window in cols.windows(2) {
        match window {
            [ArrayColumn::Separator(line), ArrayColumn::Separator(_)] => {
                index += 1;
                out.push_str(match line {
                    Line::Solid => " class=\"ml-left-solid ml-border-only\"></mtd><mtd",
                    Line::Dashed => " class=\"ml-left-dashed ml-border-only\"></mtd><mtd",
                });
                if out.len() > MATH_HTML_MAX {
                    return Err(());
                }
            }
            _ => break,
        }
    }

    match (cols.get(index), cols.get(index + 1)) {
        (Some(ArrayColumn::Separator(left)), Some(ArrayColumn::Column(align))) => {
            index += 2;
            let right = match cols.get(index) {
                Some(ArrayColumn::Separator(line)) => {
                    index += 1;
                    Some(*line)
                }
                _ => None,
            };
            push_array_cell_classes(out, Some(*left), *align, right);
        }
        (Some(ArrayColumn::Column(align)), Some(ArrayColumn::Separator(right))) => {
            index += 2;
            push_array_cell_classes(out, None, *align, Some(*right));
        }
        (Some(ArrayColumn::Column(align)), _) => {
            index += 1;
            push_array_cell_classes(out, None, *align, None);
        }
        (None, None) => out.push('>'),
        _ => return Err(()),
    }
    Ok(index)
}

fn array_align(out: &mut String, cols: &[ArrayColumn], cols_index: &mut usize) -> Result<(), ()> {
    out.push_str("</mtd><mtd");
    let rest = cols.get(*cols_index..).ok_or(())?;
    for col in rest {
        match col {
            ArrayColumn::Separator(line) => {
                *cols_index += 1;
                out.push_str(match line {
                    Line::Solid => " class=\"ml-right-solid ml-border-only\"></mtd><mtd",
                    Line::Dashed => " class=\"ml-right-dashed ml-border-only\"></mtd><mtd",
                });
                if out.len() > MATH_HTML_MAX {
                    return Err(());
                }
            }
            ArrayColumn::Column(_) => break,
        }
    }

    match (cols.get(*cols_index), cols.get(*cols_index + 1)) {
        (Some(ArrayColumn::Column(align)), Some(ArrayColumn::Separator(right))) => {
            *cols_index += 2;
            push_array_cell_classes(out, None, *align, Some(*right));
        }
        (Some(ArrayColumn::Column(align)), _) => {
            *cols_index += 1;
            push_array_cell_classes(out, None, *align, None);
        }
        _ => return Err(()),
    }
    Ok(())
}

fn array_close_line(out: &mut String, rest_cols: &[ArrayColumn]) -> Result<(), ()> {
    out.push_str("</mtd>");
    for col in rest_cols {
        match col {
            ArrayColumn::Separator(Line::Solid) => {
                out.push_str("<mtd class=\"ml-right-solid ml-border-only\"></mtd>");
            }
            ArrayColumn::Separator(Line::Dashed) => {
                out.push_str("<mtd class=\"ml-right-dashed ml-border-only\"></mtd>");
            }
            ArrayColumn::Column(_) => break,
        }
        if out.len() > MATH_HTML_MAX {
            return Err(());
        }
    }
    out.push_str("</mtr><mtr");
    Ok(())
}

fn write_env_horizontal_lines(out: &mut String, lines: &[Line]) -> Result<(), ()> {
    if lines.len() > MATH_HLINES_MAX {
        return Err(());
    }
    let mut iter = lines.iter();
    if let Some(last_line) = iter.next_back() {
        for line in iter {
            out.push_str(match line {
                Line::Solid => " class=\"ml-hline\"><mtd class=\"ml-nonumber\"></mtd></mtr><mtr",
                Line::Dashed => {
                    " class=\"ml-hdashline\"><mtd class=\"ml-nonumber\"></mtd></mtr><mtr"
                }
            });
            if out.len() > MATH_HTML_MAX {
                return Err(());
            }
        }
        out.push_str(match last_line {
            Line::Solid => " class=\"ml-hline\"",
            Line::Dashed => " class=\"ml-hdashline\"",
        });
    }
    Ok(())
}

/// Map a Greek letter or operator symbol into a Mathematical Alphanumeric block starting at `base`.
fn map_greek(base: u32, c: char) -> Option<u32> {
    let offset = match c {
        '\u{0391}'..='\u{03A1}' => c as u32 - 0x0391,
        '\u{03F4}' => 17,
        '\u{03A3}'..='\u{03A9}' => 18 + (c as u32 - 0x03A3),
        '\u{2207}' => 25,
        '\u{03B1}'..='\u{03C9}' => 26 + (c as u32 - 0x03B1),
        '\u{2202}' => 51,
        '\u{03F5}' => 52,
        '\u{03D1}' => 53,
        '\u{03F0}' => 54,
        '\u{03D5}' => 55,
        '\u{03F1}' => 56,
        '\u{03D6}' => 57,
        _ => return None,
    };
    Some(base + offset)
}

/// Map a character to its Unicode Mathematical Alphanumeric Symbols variant for `font`.
fn map_font_char(font: Font, c: char) -> char {
    let code = match (font, c) {
        (Font::BoldScript, 'A'..='Z') => c as u32 + 0x1D48F,
        (Font::BoldScript, 'a'..='z') => c as u32 + 0x1D489,

        (Font::BoldItalic, 'A'..='Z') => c as u32 + 0x1D427,
        (Font::BoldItalic, 'a'..='z') => c as u32 + 0x1D421,
        (Font::BoldItalic, _) => map_greek(0x1D71C, c).unwrap_or(c as u32),

        (Font::Bold, 'A'..='Z') => c as u32 + 0x1D3BF,
        (Font::Bold, 'a'..='z') => c as u32 + 0x1D3B9,
        (Font::Bold, '\u{03DC}' | '\u{03DD}') => c as u32 + 0x1D3EE,
        (Font::Bold, '0'..='9') => c as u32 + 0x1D79E,
        (Font::Bold, _) => map_greek(0x1D6A8, c).unwrap_or(c as u32),

        (Font::Fraktur, 'A' | 'B' | 'D'..='G' | 'J'..='Q' | 'S'..='Y') => c as u32 + 0x1D4C3,
        (Font::Fraktur, 'C') => c as u32 + 0x20EA,
        (Font::Fraktur, 'H') => 0x210C,
        (Font::Fraktur, 'I') => 0x2111,
        (Font::Fraktur, 'R') => c as u32 + 0x20CA,
        (Font::Fraktur, 'Z') => c as u32 + 0x20CE,
        (Font::Fraktur, 'a'..='z') => c as u32 + 0x1D4BD,

        (Font::Script, 'A' | 'C' | 'D' | 'G' | 'J' | 'K' | 'N'..='Q' | 'S'..='Z') => {
            c as u32 + 0x1D45B
        }
        (Font::Script, 'B') => c as u32 + 0x20EA,
        (Font::Script, 'E' | 'F') => c as u32 + 0x20EB,
        (Font::Script, 'H') => c as u32 + 0x20C3,
        (Font::Script, 'I') => c as u32 + 0x20C7,
        (Font::Script, 'L') => c as u32 + 0x20C6,
        (Font::Script, 'M') => c as u32 + 0x20E6,
        (Font::Script, 'R') => c as u32 + 0x20C9,
        (Font::Script, 'a'..='d' | 'f' | 'h'..='n' | 'p'..='z') => c as u32 + 0x1D455,
        (Font::Script, 'e') => c as u32 + 0x20CA,
        (Font::Script, 'g') => c as u32 + 0x20A3,
        (Font::Script, 'o') => c as u32 + 0x20C5,

        (Font::Monospace, 'A'..='Z') => c as u32 + 0x1D62F,
        (Font::Monospace, 'a'..='z') => c as u32 + 0x1D629,
        (Font::Monospace, '0'..='9') => c as u32 + 0x1D7C6,

        (Font::SansSerif, 'A'..='Z') => c as u32 + 0x1D55F,
        (Font::SansSerif, 'a'..='z') => c as u32 + 0x1D559,
        (Font::SansSerif, '0'..='9') => c as u32 + 0x1D7B2,

        (Font::DoubleStruck, 'A' | 'B' | 'D'..='G' | 'I'..='M' | 'O' | 'S'..='Y') => {
            c as u32 + 0x1D4F7
        }
        (Font::DoubleStruck, 'C') => c as u32 + 0x20BF,
        (Font::DoubleStruck, 'H') => c as u32 + 0x20C5,
        (Font::DoubleStruck, 'N') => c as u32 + 0x20C7,
        (Font::DoubleStruck, 'P' | 'Q') => c as u32 + 0x20C9,
        (Font::DoubleStruck, 'R') => c as u32 + 0x20CB,
        (Font::DoubleStruck, 'Z') => c as u32 + 0x20CA,
        (Font::DoubleStruck, 'a'..='z') => c as u32 + 0x1D4F1,
        (Font::DoubleStruck, '0'..='9') => c as u32 + 0x1D7A8,

        (Font::DoubleStruckItalic, 'D') => c as u32 + 0x2101,
        (Font::DoubleStruckItalic, 'd' | 'e') => c as u32 + 0x20E2,
        (Font::DoubleStruckItalic, 'i' | 'j') => c as u32 + 0x20DF,

        (Font::Italic, 'A'..='Z') => c as u32 + 0x1D3F3,
        (Font::Italic, 'a'..='g' | 'i'..='z') => c as u32 + 0x1D3ED,
        (Font::Italic, 'h') => c as u32 + 0x20A6,
        (Font::Italic, _) => map_greek(0x1D6E2, c).unwrap_or(c as u32),

        (Font::BoldFraktur, 'A'..='Z') => c as u32 + 0x1D52B,
        (Font::BoldFraktur, 'a'..='z') => c as u32 + 0x1D525,

        (Font::SansSerifBoldItalic, 'A'..='Z') => c as u32 + 0x1D5FB,
        (Font::SansSerifBoldItalic, 'a'..='z') => c as u32 + 0x1D5F5,
        (Font::SansSerifBoldItalic, _) => map_greek(0x1D790, c).unwrap_or(c as u32),

        (Font::SansSerifItalic, 'A'..='Z') => c as u32 + 0x1D5C7,
        (Font::SansSerifItalic, 'a'..='z') => c as u32 + 0x1D5C1,

        (Font::BoldSansSerif, 'A'..='Z') => c as u32 + 0x1D593,
        (Font::BoldSansSerif, 'a'..='z') => c as u32 + 0x1D58D,
        (Font::BoldSansSerif, '0'..='9') => c as u32 + 0x1D7BC,
        (Font::BoldSansSerif, _) => map_greek(0x1D756, c).unwrap_or(c as u32),

        _ => c as u32,
    };
    char::from_u32(code).unwrap_or(c)
}
