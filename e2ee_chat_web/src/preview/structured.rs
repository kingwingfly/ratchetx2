use super::{CELLS_MAX, COLS_MAX, ROWS_MAX};

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
        } else if self.rows.len() >= ROWS_MAX {
            parts.push(format!("the first {ROWS_MAX} rows"));
        }
        if self.truncated_columns {
            parts.push(format!("the first {COLS_MAX} columns per row"));
        }
        if parts.is_empty() {
            parts.push(format!("the first {ROWS_MAX} rows"));
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
    let mut more = false;
    let mut truncated_columns = false;
    let mut truncated_cells = false;
    let mut total_cells = 0usize;
    for record in reader.records() {
        let Ok(record) = record else { break };
        if rows.len() == ROWS_MAX {
            more = true;
            break;
        }
        let mut row: Vec<String> = record.iter().take(COLS_MAX).map(str::to_string).collect();
        if record.len() > COLS_MAX {
            let extra = record.len() - COLS_MAX;
            let suffix = if extra == 1 { "column" } else { "columns" };
            row.push(format!("… (+{extra} more {suffix})"));
            truncated_columns = true;
            more = true;
        }
        if !rows.is_empty() && total_cells.saturating_add(row.len()) > CELLS_MAX {
            truncated_cells = true;
            more = true;
            break;
        }
        total_cells = total_cells.saturating_add(row.len());
        rows.push(row);
    }
    Table {
        rows,
        more,
        truncated_rows: false,
        truncated_columns,
        truncated_cells,
    }
}

/// The lines of the unified diff `text`, each with its kind.
pub(super) fn diff(text: &str) -> Diff {
    let mut in_hunk = false;
    let lines = text
        .lines()
        .map(|line| {
            let kind = if line.starts_with("@@") {
                in_hunk = true;
                DiffLine::Hunk
            } else if line.starts_with("diff ") || line.starts_with("--- ") && !in_hunk {
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
            (kind, line.to_string())
        })
        .collect();
    Diff {
        lines,
        truncated: false,
    }
}

/// The content lines of a vCard or iCalendar file: unfolded, each as its name, upper case, and
/// its value, unescaped.
fn content_lines(text: &str) -> Vec<(String, String)> {
    let mut lines: Vec<String> = vec![];
    for line in text.lines() {
        match (line.strip_prefix([' ', '\t']), lines.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ => lines.push(line.to_string()),
        }
    }
    lines
        .iter()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.split(';').next()?.trim().to_uppercase();
            let value = unescape_content_value(value);
            Some((name, value))
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

/// The contacts of the vCard file `text`.
pub(super) fn contacts(text: &str) -> Cards {
    let mut cards = vec![];
    let mut card: Option<Card> = None;
    for (name, value) in content_lines(text) {
        match (name.as_str(), &mut card) {
            ("BEGIN", None) if value.eq_ignore_ascii_case("VCARD") => {
                card = Some(Card {
                    title: String::new(),
                    fields: vec![],
                });
            }
            ("END", Some(_)) if value.eq_ignore_ascii_case("VCARD") => cards.extend(card.take()),
            ("FN", Some(card)) => card.title = value,
            // The structured name, if there is no formatted one: given then family name.
            ("N", Some(card)) if card.title.is_empty() => {
                let mut parts = value.split(';');
                let family = parts.next().unwrap_or_default();
                let given = parts.next().unwrap_or_default();
                card.title = format!("{given} {family}").trim().to_string();
            }
            (name, Some(card)) => {
                let label = match name {
                    "TEL" => "Phone",
                    "EMAIL" => "Email",
                    "ORG" => "Organization",
                    "TITLE" => "Title",
                    "ADR" => "Address",
                    "URL" => "Web",
                    "BDAY" => "Birthday",
                    "NOTE" => "Note",
                    _ => continue,
                };
                let value = match name {
                    "ADR" | "ORG" => joined(&value),
                    "BDAY" => date(&value),
                    _ => value,
                };
                card.fields.push((label, value));
            }
            _ => {}
        }
    }
    Cards {
        items: cards,
        truncated_cards: false,
        truncated_fields: false,
    }
}

/// The events of the iCalendar file `text`, without their alarms.
pub(super) fn events(text: &str) -> Cards {
    let mut cards = vec![];
    let mut card: Option<Card> = None;
    let mut nested = 0;
    for (name, value) in content_lines(text) {
        match (name.as_str(), &mut card) {
            ("BEGIN", None) if value.eq_ignore_ascii_case("VEVENT") => {
                card = Some(Card {
                    title: String::new(),
                    fields: vec![],
                });
            }
            ("BEGIN", Some(_)) => nested += 1,
            ("END", Some(_)) if nested > 0 => nested -= 1,
            ("END", Some(_)) if value.eq_ignore_ascii_case("VEVENT") => cards.extend(card.take()),
            (_, Some(_)) if nested > 0 => {}
            ("SUMMARY", Some(card)) => card.title = value,
            (name, Some(card)) => {
                let label = match name {
                    "DTSTART" => "Starts",
                    "DTEND" => "Ends",
                    "LOCATION" => "Where",
                    "ORGANIZER" => "Organizer",
                    "ATTENDEE" => "Attendee",
                    "RRULE" => "Repeats",
                    "DESCRIPTION" => "Description",
                    _ => continue,
                };
                let value = match name {
                    "DTSTART" | "DTEND" => date(&value),
                    "ORGANIZER" | "ATTENDEE" => value
                        .trim_start_matches("mailto:")
                        .trim_start_matches("MAILTO:")
                        .to_string(),
                    _ => value,
                };
                card.fields.push((label, value));
            }
            _ => {}
        }
    }
    Cards {
        items: cards,
        truncated_cards: false,
        truncated_fields: false,
    }
}

/// A structured value's parts, such as an address's, joined by commas, the empty ones left out.
fn joined(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A date or date-time such as `20261025T090000Z` as `2026-10-25 09:00 UTC`; any other as is.
fn date(value: &str) -> String {
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
            let zone = if value.ends_with('Z') { " UTC" } else { "" };
            format!("{date} {hour}:{minute}{zone}")
        }
        _ => date,
    }
}
