use pulldown_latex::event::Font;

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
pub(super) fn map_font_char(font: Font, c: char) -> char {
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
