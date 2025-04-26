use std::{
    fs,
    io::Read as _,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

use image::load_from_memory;
use lru::LruCache;
use mime::{IMAGE, TEXT};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph, Scrollbar, ScrollbarState},
};
use ratatui_image::{FilterType, Resize, StatefulImage, picker::Picker};
use regex::Regex;
use tui_textarea::{Input, TextArea};
use unicode_width::UnicodeWidthStr;

use crate::message::MessageContent;

pub struct Explore {}

#[derive(Debug)]
pub struct ExploreState {
    pub selected: usize,
    pub paths: Vec<PathBuf>,
    textarea: TextArea<'static>,
    lru: LruCache<PathBuf, Vec<u8>>,
    picker: Picker,
}

impl Default for ExploreState {
    fn default() -> Self {
        Self {
            selected: 0,
            paths: collect_paths(std::env::current_dir().unwrap()),
            textarea: Default::default(),
            lru: LruCache::new(NonZeroUsize::new(16).unwrap()),
            picker: Picker::from_query_stdio().unwrap(),
        }
    }
}

impl ExploreState {
    pub fn parent(&self) -> &Path {
        let selected = &self.paths[self.selected];
        selected.parent().unwrap_or(selected.as_path())
    }

    pub fn back(&mut self) {
        if let Some(p) = self.parent().ancestors().nth(1) {
            self.paths = collect_paths(p);
            self.selected = 0;
        }
    }

    pub fn forward(&mut self) {
        if self.paths[self.selected]
            .read_dir()
            .ok()
            .and_then(|rd| rd.filter_map(|p| p.ok()).next())
            .is_some()
        {
            self.paths = collect_paths(&self.paths[self.selected]);
            self.selected = 0;
        }
    }

    pub fn input(&mut self, input: impl Into<Input>) {
        self.textarea.input(input);
        if let Ok(regex) = Regex::new(&self.textarea.lines().join("\n")) {
            let all = collect_paths(self.parent());
            let filtered = all
                .iter()
                .filter(|p| {
                    p.file_name()
                        .map_or_else(|| false, |f| regex.is_match(&f.to_string_lossy()))
                })
                .cloned()
                .collect::<Vec<_>>();
            if !filtered.is_empty() {
                self.paths = filtered;
            } else {
                self.paths = all;
            }
            self.selected = 0;
        }
    }

    pub fn message(&self) -> Option<MessageContent> {
        let selected = &self.paths[self.selected];
        mime_guess::from_path(selected)
            .first()
            .and_then(|mime| match mime.type_() {
                TEXT => fs::read_to_string(selected).map(MessageContent::Text).ok(),
                IMAGE => fs::read(selected).map(MessageContent::Image).ok(),
                _ => None,
            })
    }
}

impl StatefulWidget for Explore {
    type State = ExploreState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let block = Block::bordered()
            .border_style(Style::default().green())
            .padding(Padding::proportional(1));
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Fill(1)])
            .split(block.inner(area));
        block.render(area, buf);

        Block::default()
            .borders(Borders::BOTTOM)
            .render(chunks[0], buf);
        let search_bar = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(3), Constraint::Fill(1)])
            .split(chunks[0]);
        Text::raw("🔍").centered().render(search_bar[0], buf);
        state.textarea.render(search_bar[1], buf);

        let display = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Fill(1)])
            .split(chunks[1]);

        let block = Block::bordered().padding(Padding::left(1));
        let files = block.inner(display[0]);
        block.render(display[0], buf);
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Fill(1), Constraint::Length(1)])
            .split(files);
        Scrollbar::default().render(
            chunks[1],
            buf,
            &mut ScrollbarState::new(state.paths.len()).position(state.selected),
        );

        let page = state.selected / (files.height as usize);
        let lines = state
            .paths
            .iter()
            .skip(page * files.height as usize)
            .take(files.height as usize)
            .enumerate()
            .map(|(i, p)| {
                let mut span = Span::raw(p.file_name().unwrap().to_string_lossy());
                if p.is_dir() {
                    span = span.blue();
                }
                if i == state.selected % (files.height as usize) {
                    span = span.underlined();
                }
                Line::default().spans([span])
            })
            .collect::<Vec<_>>();
        Paragraph::new(lines).render(chunks[0], buf);

        let block = Block::bordered().padding(Padding::horizontal(1));
        let preview = block.inner(display[1]);
        block.render(display[1], buf);
        let selected = &state.paths[state.selected];
        if let Some(mime) = mime_guess::from_path(selected).first() {
            match mime.type_() {
                TEXT => {
                    let bytes = state.lru.get_or_insert(selected.clone(), || {
                        fs::File::open(selected)
                            .map(|mut file| {
                                let mut lines = 0;
                                let mut buffer = [0; 1024];
                                let mut bytes: Vec<u8> = vec![];
                                while let Ok(n) = file.read(&mut buffer) {
                                    if n == 0 {
                                        break;
                                    }
                                    bytes.extend(&buffer[..n]);
                                    let chunk = String::from_utf8_lossy(&buffer[..n]);
                                    for line in chunk.lines() {
                                        lines += (line.width_cjk() as u16 % preview.width) + 1;
                                    }
                                    if lines > preview.height {
                                        break;
                                    }
                                }
                                bytes
                            })
                            .unwrap_or_default()
                    });
                    let text = String::from_utf8_lossy(bytes);
                    let lines = text.lines().map(Into::into).collect::<Vec<_>>();
                    Paragraph::new(lines).render(preview, buf);
                }
                IMAGE => {
                    let bytes = state.lru.get_or_insert(selected.clone(), || {
                        std::fs::read(selected).unwrap_or_default()
                    });
                    if let Ok(image) = load_from_memory(bytes) {
                        let mut image = state.picker.new_resize_protocol(image);
                        image.resize_encode(&Resize::Fit(Some(FilterType::CatmullRom)), preview);
                        StatefulImage::default().render(preview, buf, &mut image);
                    }
                }
                _ => {}
            }
        }
    }
}

fn collect_paths(parent: impl AsRef<Path>) -> Vec<PathBuf> {
    parent
        .as_ref()
        .read_dir()
        .unwrap()
        .filter_map(|res| res.ok())
        .map(|e| e.path())
        .collect::<Vec<_>>()
}
