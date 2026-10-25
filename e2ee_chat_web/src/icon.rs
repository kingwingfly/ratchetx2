//! The icons of the buttons that need no words: outlines on a 24-pixel grid, which the stylesheet
//! strokes in the button's color, so that they take its hover, primary and disabled looks.

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// A paper plane.
    Send,
    /// A paper clip.
    Attach,
    Lock,
    /// A pencil on a sheet: a new chat.
    Compose,
    /// Two arrows chasing each other round.
    Sync,
    Key,
    Info,
    Close,
    Back,
    Download,
    /// Two sheets, one over the other.
    Copy,
    Tick,
    /// Play: an upload goes on.
    Resume,
    Previous,
    Next,
    Up,
    Down,
    /// Corners out, and in.
    FullScreen,
    LeaveFullScreen,
    /// A presentation board, and a page of text.
    Slides,
    Document,
}

impl Icon {
    fn paths(self) -> &'static [&'static str] {
        match self {
            Self::Send => &["M21 3 10.5 13.5", "M21 3l-6.5 18-4-7.5-7.5-4z"],
            Self::Attach => &[
                "M20.5 11.5l-8.2 8.2a5 5 0 0 1-7.1-7.1l8.6-8.6a3.3 3.3 0 0 1 4.7 4.7l-8.6 8.6a1.7 1.7 0 0 1-2.4-2.4l7.9-7.9",
            ],
            Self::Lock => &[
                "M6 11h12a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2z",
                "M8 11V7a4 4 0 0 1 8 0v4",
            ],
            Self::Compose => &[
                "M12 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6",
                "M17.5 3.5a2.1 2.1 0 0 1 3 3L12 15l-4 1 1-4z",
            ],
            Self::Sync => &[
                "M20 11a8 8 0 0 0-14.3-4.9L4 8",
                "M4 3v5h5",
                "M4 13a8 8 0 0 0 14.3 4.9L20 16",
                "M20 21v-5h-5",
            ],
            Self::Key => &[
                "M10.6 13.4a4.5 4.5 0 1 1-6.4 6.4 4.5 4.5 0 0 1 6.4-6.4z",
                "M10.6 13.4 20 4",
                "M16.5 7.5l3 3",
                "M14 10l2 2",
            ],
            Self::Info => &["M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18z", "M12 11v6", "M12 7.5v.01"],
            Self::Close => &["M6 6l12 12", "M18 6 6 18"],
            Self::Back => &["M19 12H5", "M11 6l-6 6 6 6"],
            Self::Download => &["M12 4v11", "M7 10l5 5 5-5", "M5 20h14"],
            Self::Copy => &[
                "M11 9h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2z",
                "M15 9V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h4",
            ],
            Self::Tick => &["M4 12.5l5 5L20 6.5"],
            Self::Resume => &["M7 4.5v15l12-7.5z"],
            Self::Previous => &["M15 6l-6 6 6 6"],
            Self::Next => &["M9 6l6 6-6 6"],
            Self::Up => &["M6 15l6-6 6 6"],
            Self::Down => &["M6 9l6 6 6-6"],
            Self::FullScreen => &[
                "M4 9V5a1 1 0 0 1 1-1h4",
                "M15 4h4a1 1 0 0 1 1 1v4",
                "M20 15v4a1 1 0 0 1-1 1h-4",
                "M9 20H5a1 1 0 0 1-1-1v-4",
            ],
            Self::LeaveFullScreen => &[
                "M9 4v4a1 1 0 0 1-1 1H4",
                "M20 9h-4a1 1 0 0 1-1-1V4",
                "M15 20v-4a1 1 0 0 1 1-1h4",
                "M4 15h4a1 1 0 0 1 1 1v4",
            ],
            Self::Slides => &[
                "M3 4h18",
                "M4 4v11a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V4",
                "M12 16v4",
                "M8 20h8",
            ],
            Self::Document => &[
                "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z",
                "M14 3v5h5",
                "M9 13h6",
                "M9 17h6",
            ],
        }
    }
}

/// The icon `icon`, for a button that names it in its `title` and `aria-label`.
pub fn icon(icon: Icon) -> impl IntoView {
    view! {
        <svg class="glyph" viewBox="0 0 24 24" aria-hidden="true">
            {icon.paths().iter().map(|path| view! { <path d=*path /> }).collect_view()}
        </svg>
    }
}
