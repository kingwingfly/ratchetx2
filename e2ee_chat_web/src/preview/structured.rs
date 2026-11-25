use super::{
    CARD_FIELDS_MAX, CARDS_MAX, CELLS_MAX, COLS_MAX, DIFF_LINES_MAX, PreviewBudget, ROWS_MAX,
};

/// The rows of a table, the first one as its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub rows: Vec<Vec<String>>,
    /// Whether the table was truncated by [`ROWS_MAX`], [`COLS_MAX`], [`CELLS_MAX`], or a parse error.
    pub more: bool,
    /// Whether one or more rows were omitted due to [`ROWS_MAX`].
    pub truncated_rows: bool,
    /// Whether one or more rows had more than [`COLS_MAX`] columns.
    pub truncated_columns: bool,
    /// Whether rendering stopped early due to [`CELLS_MAX`].
    pub truncated_cells: bool,
}

impl Table {
    /// Human-readable truncation notice, if any limit was reached.
    pub fn notice(&self) -> Option<String> {
        if !self.more {
            return None;
        }
        let mut parts = Vec::new();
        if self.truncated_cells {
            parts.push(format!("at most {CELLS_MAX} cells"));
        } else if self.truncated_rows {
            parts.push(format!("the first {ROWS_MAX} rows"));
        }
        if self.truncated_columns {
            parts.push(format!("the first {COLS_MAX} columns per row"));
        }
        if parts.is_empty() {
            return Some("The rest of the table could not be parsed.".to_string());
        }
        Some(format!("Only {} show.", parts.join(" and ")))
    }
}

/// A bounded list of contact or event cards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cards {
    pub items: Vec<Card>,
    pub truncated_cards: bool,
    pub truncated_fields: bool,
}

impl Cards {
    pub fn notice(&self) -> Option<String> {
        if !self.truncated_cards && !self.truncated_fields {
            return None;
        }
        let mut parts = Vec::new();
        if self.truncated_cards {
            parts.push(format!("the first {} entries", self.items.len()));
        }
        if self.truncated_fields {
            parts.push("bounded fields per entry".to_string());
        }
        Some(format!("Only {} show.", parts.join(" with ")))
    }
}

/// A bounded unified diff listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    pub lines: Vec<(DiffLine, String)>,
    pub truncated: bool,
}

impl Diff {
    pub fn notice(&self) -> Option<String> {
        self.truncated
            .then(|| format!("Only the first {} lines show.", self.lines.len()))
    }
}

/// A contact or an event: its name, then its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub title: String,
    pub fields: Vec<(&'static str, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLine {
    /// `--- a/file` or `+++ b/file`, or what comes before the hunks.
    File,
    /// `@@ -1,2 +1,3 @@`.
    Hunk,
    Added,
    Removed,
    Context,
}

/// The CSV `text`, separated by `delimiter`, as a table bounded by [`ROWS_MAX`], [`COLS_MAX`],
/// and [`CELLS_MAX`].
pub(super) fn table(text: &str, delimiter: u8) -> Table {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut rows = vec![];
    let mut row_budget = PreviewBudget::new(ROWS_MAX);
    let mut cell_budget = PreviewBudget::new(CELLS_MAX);
    let mut truncated_columns = false;
    let mut parse_error = false;
    for record in reader.records() {
        let Ok(record) = record else {
            parse_error = true;
            break;
        };
        if !row_budget.try_push() {
            break;
        }
        let mut row: Vec<String> = record.iter().take(COLS_MAX).map(str::to_string).collect();
        if record.len() > COLS_MAX {
            let extra = record.len() - COLS_MAX;
            let suffix = if extra == 1 { "column" } else { "columns" };
            row.push(format!("… (+{extra} more {suffix})"));
            truncated_columns = true;
        }
        if !rows.is_empty() && !cell_budget.take(row.len()) {
            break;
        }
        if rows.is_empty() {
            let _ = cell_budget.take(row.len());
        }
        rows.push(row);
    }
    let truncated_rows = row_budget.is_truncated();
    let truncated_cells = cell_budget.is_truncated();
    let more = truncated_rows || truncated_columns || truncated_cells || parse_error;
    Table {
        rows,
        more,
        truncated_rows,
        truncated_columns,
        truncated_cells,
    }
}

/// The lines of the unified diff `text`, each with its kind, bounded to [`DIFF_LINES_MAX`].
pub(super) fn diff(text: &str) -> Diff {
    let mut raw_lines = text.lines();
    let mut current = raw_lines.next();
    let mut next = raw_lines.next();
    let mut after_next = raw_lines.next();

    let mut budget = PreviewBudget::new(DIFF_LINES_MAX);
    let mut lines = Vec::new();
    let mut in_hunk = false;

    while let Some(line) = current {
        if !budget.try_push() {
            break;
        }
        let is_file_header_transition = line.starts_with("diff ")
            || (line.starts_with("--- ")
                && (!in_hunk
                    || (next.is_some_and(|n| n.starts_with("+++ "))
                        && (line.starts_with("--- a/")
                            || line.starts_with("--- /dev/null")
                            || after_next.is_none_or(|a| a.starts_with("@@ "))))));
        let kind = if line.starts_with("@@") {
            in_hunk = true;
            DiffLine::Hunk
        } else if is_file_header_transition {
            in_hunk = false;
            DiffLine::File
        } else if !in_hunk {
            DiffLine::File
        } else if line.starts_with('+') {
            DiffLine::Added
        } else if line.starts_with('-') {
            DiffLine::Removed
        } else {
            DiffLine::Context
        };
        lines.push((kind, line.to_string()));

        current = next;
        next = after_next;
        after_next = raw_lines.next();
    }

    Diff {
        lines,
        truncated: budget.is_truncated(),
    }
}

struct ContentLine {
    name: String,
    tzid: Option<String>,
    raw_value: String,
}

/// Find the index of the first `:` outside double-quoted parameter values.
fn find_unquoted_colon(line: &str) -> Option<usize> {
    let mut in_quotes = false;
    for (idx, b) in line.bytes().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b':' if !in_quotes => return Some(idx),
            _ => {}
        }
    }
    None
}

/// Split a property header on `;` outside double-quoted parameter values.
fn split_unquoted_semicolons(head: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (idx, b) in head.bytes().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => {
                parts.push(&head[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&head[start..]);
    parts
}

/// The content lines of a vCard or iCalendar file: unfolded, parsed without splitting on colons
/// inside quoted parameters, with Apple group prefixes (`item1.EMAIL`) stripped and `TZID`
/// extracted. Values remain raw so structured properties (`N`/`ADR`/`ORG`) split on unescaped `;`
/// before unescaping.
fn content_lines(text: &str) -> Vec<ContentLine> {
    let mut unfolded: Vec<String> = vec![];
    for line in text.lines() {
        match (line.strip_prefix([' ', '\t']), unfolded.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ => unfolded.push(line.to_string()),
        }
    }
    unfolded
        .iter()
        .filter_map(|line| {
            let colon = find_unquoted_colon(line)?;
            let head = &line[..colon];
            let raw_value = &line[colon + 1..];
            let mut segments = split_unquoted_semicolons(head).into_iter();
            let raw_name = segments.next()?.trim();
            // Strip optional RFC 6350 / Apple group prefix (e.g. `item1.EMAIL` -> `EMAIL`).
            let name = raw_name
                .rsplit_once('.')
                .map_or(raw_name, |(_, prop)| prop)
                .trim()
                .to_ascii_uppercase();
            if name.is_empty() {
                return None;
            }
            let mut tzid = None;
            for param in segments {
                if let Some((key, val)) = param.split_once('=')
                    && key.trim().eq_ignore_ascii_case("TZID")
                {
                    let trimmed = val.trim().trim_matches('"').trim();
                    if !trimmed.is_empty() {
                        tzid = Some(trimmed.to_string());
                    }
                }
            }
            Some(ContentLine {
                name,
                tzid,
                raw_value: raw_value.to_string(),
            })
        })
        .collect()
}

/// Unescape RFC 5545 / RFC 6350 backslash sequences in a single pass so `\\n` becomes `\n`
/// (literal backslash + `n`) rather than a backslash followed by a newline.
fn unescape_content_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(',') => out.push(','),
                Some(';') => out.push(';'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Split a structured vCard value (`N`, `ADR`, `ORG`) on unescaped `;` boundaries first, then
/// unescape each part individually so `\;` stays inside its component rather than splitting it.
fn split_escaped_semicolons(raw: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if bytes[i] == b';' {
            parts.push(unescape_content_value(&raw[start..i]));
            start = i + 1;
        }
        i += 1;
    }
    parts.push(unescape_content_value(&raw[start..]));
    parts
}

/// Shared bounded parser for vCard (`VCARD`) and iCalendar (`VEVENT`) card collections,
/// recovering cleanly from unclosed nested `BEGIN` blocks (e.g. an unclosed `VALARM` followed by
/// `END:VEVENT` or another `BEGIN:VEVENT`).
fn parse_cards(
    text: &str,
    component: &str,
    mut apply_field: impl FnMut(&mut Card, &ContentLine, &mut PreviewBudget),
) -> Cards {
    let mut cards = Vec::new();
    let mut card_budget = PreviewBudget::new(CARDS_MAX);
    let mut truncated_fields = false;
    let mut current: Option<(Card, PreviewBudget)> = None;
    let mut nested: Vec<String> = Vec::new();

    for line in content_lines(text) {
        let name = line.name.as_str();
        if name == "BEGIN" {
            let block = line.raw_value.trim();
            if block.eq_ignore_ascii_case(component) {
                // Recover if a previous card was never closed before a new `BEGIN:<component>`.
                if let Some((prev, prev_fields)) = current.take() {
                    truncated_fields |= prev_fields.is_truncated();
                    if card_budget.try_push() {
                        cards.push(prev);
                    } else {
                        break;
                    }
                }
                nested.clear();
                current = Some((
                    Card {
                        title: String::new(),
                        fields: Vec::new(),
                    },
                    PreviewBudget::new(CARD_FIELDS_MAX),
                ));
            } else if current.is_some() && nested.len() < 32 {
                nested.push(block.to_ascii_uppercase());
            }
            continue;
        }

        if name == "END" {
            let block = line.raw_value.trim();
            if block.eq_ignore_ascii_case(component) {
                nested.clear();
                if let Some((finished, field_budget)) = current.take() {
                    truncated_fields |= field_budget.is_truncated();
                    if card_budget.try_push() {
                        cards.push(finished);
                    } else {
                        break;
                    }
                }
            } else if let Some(pos) = nested.iter().rposition(|n| n.eq_ignore_ascii_case(block)) {
                nested.truncate(pos);
            }
            continue;
        }

        if !nested.is_empty() {
            continue;
        }
        if let Some((card, field_budget)) = current.as_mut() {
            apply_field(card, &line, field_budget);
        }
    }

    Cards {
        items: cards,
        truncated_cards: card_budget.is_truncated(),
        truncated_fields,
    }
}

/// The contacts of the vCard file `text`, bounded by [`CARDS_MAX`] and [`CARD_FIELDS_MAX`].
pub(super) fn contacts(text: &str) -> Cards {
    parse_cards(text, "VCARD", |card, line, field_budget| {
        match line.name.as_str() {
            "FN" => card.title = unescape_content_value(&line.raw_value),
            // The structured name, if there is no formatted one: given then family name.
            "N" if card.title.is_empty() => {
                let parts = split_escaped_semicolons(&line.raw_value);
                let family = parts.first().map(String::as_str).unwrap_or_default();
                let given = parts.get(1).map(String::as_str).unwrap_or_default();
                card.title = format!("{given} {family}").trim().to_string();
            }
            name => {
                let label = match name {
                    "TEL" => "Phone",
                    "EMAIL" => "Email",
                    "ORG" => "Organization",
                    "TITLE" => "Title",
                    "ADR" => "Address",
                    "URL" => "Web",
                    "BDAY" => "Birthday",
                    "NOTE" => "Note",
                    _ => return,
                };
                if !field_budget.try_push() {
                    return;
                }
                let value = match name {
                    "ADR" | "ORG" => joined(&line.raw_value),
                    "BDAY" => date(&unescape_content_value(&line.raw_value), None),
                    _ => unescape_content_value(&line.raw_value),
                };
                card.fields.push((label, value));
            }
        }
    })
}

/// The events of the iCalendar file `text`, without their alarms, bounded by [`CARDS_MAX`] and
/// [`CARD_FIELDS_MAX`].
pub(super) fn events(text: &str) -> Cards {
    parse_cards(text, "VEVENT", |card, line, field_budget| {
        match line.name.as_str() {
            "SUMMARY" => card.title = unescape_content_value(&line.raw_value),
            name => {
                let label = match name {
                    "DTSTART" => "Starts",
                    "DTEND" => "Ends",
                    "LOCATION" => "Where",
                    "ORGANIZER" => "Organizer",
                    "ATTENDEE" => "Attendee",
                    "RRULE" => "Repeats",
                    "DESCRIPTION" => "Description",
                    _ => return,
                };
                if !field_budget.try_push() {
                    return;
                }
                let unescaped = unescape_content_value(&line.raw_value);
                let value = match name {
                    "DTSTART" | "DTEND" => date(&unescaped, line.tzid.as_deref()),
                    "ORGANIZER" | "ATTENDEE" => strip_mailto_prefix(&unescaped),
                    _ => unescaped,
                };
                card.fields.push((label, value));
            }
        }
    })
}

fn strip_mailto_prefix(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed
        .as_bytes()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"mailto:"))
    {
        trimmed[7..].to_string()
    } else {
        trimmed.to_string()
    }
}

/// A structured value's parts, such as an address's, split on unescaped `;`, unescaped, and
/// joined by commas with empty parts left out.
fn joined(raw: &str) -> String {
    split_escaped_semicolons(raw)
        .into_iter()
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A date or date-time such as `20261025T090000Z` as `2026-10-25 09:00 UTC` (or with `TZID`
/// appended when present); any other as is.
fn date(value: &str, tzid: Option<&str>) -> String {
    let digits = |range: std::ops::Range<usize>| {
        value
            .get(range)
            .filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(4..6), digits(6..8)) else {
        return value.to_string();
    };
    let date = format!("{year}-{month}-{day}");
    match (value.get(8..9), digits(9..11), digits(11..13)) {
        (Some("T"), Some(hour), Some(minute)) => {
            if value.ends_with('Z') {
                format!("{date} {hour}:{minute} UTC")
            } else if let Some(tz) = tzid.filter(|tz| !tz.is_empty()) {
                format!("{date} {hour}:{minute} {tz}")
            } else {
                format!("{date} {hour}:{minute}")
            }
        }
        _ => date,
    }
}
