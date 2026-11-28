use std::fmt::Write as _;

use pulldown_latex::{
    config::DisplayMode,
    event::{
        ArrayColumn, ColorChange, ColorTarget, ColumnAlignment, Content, DelimiterSize,
        DelimiterType, Dimension, DimensionUnit, EnvironmentFlow, Event as LatexEvent, Font,
        Grouping, Line, ScriptPosition, ScriptType, StateChange, Style, Visual,
    },
};

use super::super::sanitize::{math_dimension_unit_max, push_escaped_char, push_escaped_text};
use super::fonts::map_font_char;

/// Maximum MathML group/script/visual nesting depth before falling back to raw TeX.
const MATH_DEPTH_MAX: usize = 128;
/// Maximum columns/separators allowed in an `\begin{array}{...}` specification.
const MATH_ARRAY_COLS_MAX: usize = 128;
/// Maximum consecutive horizontal lines (`\hline` / `\hdashline`) emitted at one row boundary.
const MATH_HLINES_MAX: usize = 32;
/// Maximum output bytes for a single MathML expression before falling back to raw TeX.
const MATH_HTML_MAX: usize = 256 * 1024;

/// Strict HTML-escaping, zero-inline-style MathML renderer walking `pulldown-latex` events
/// directly.
pub(in crate::markdown) struct MathmlRenderer<'a> {
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
    pub(in crate::markdown) fn new(
        events: &'a [LatexEvent<'a>],
        display_mode: DisplayMode,
    ) -> Self {
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

    pub(in crate::markdown) fn render(mut self) -> Result<String, ()> {
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
