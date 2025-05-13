use core::fmt;

#[derive(Debug, Default, Clone)]
pub enum Screen {
    #[default]
    Main,
    Settings,
    Quit,
    Hint(String),
    PushInitMsg,
    HandleInitMsg,
    ListInitMsg,
    SelectFile,
}

impl fmt::Display for Screen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Screen::Main => write!(f, "Main"),
            Screen::Settings => write!(f, "Settings"),
            Screen::Quit => write!(f, "Quit"),
            Screen::Hint(msg) => write!(f, "Hint: {}", msg),
            Screen::PushInitMsg => write!(f, "PushInitMsg"),
            Screen::HandleInitMsg => write!(f, "HandleInitMsg"),
            Screen::ListInitMsg => write!(f, "ListInitMsg"),
            Screen::SelectFile => write!(f, "SelectFile"),
        }
    }
}
