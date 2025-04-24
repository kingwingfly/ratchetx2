#[derive(Debug, Default, PartialEq)]
pub enum Navigation {
    #[default]
    Contacts,
    Conversation,
    Input,
}

#[derive(Debug, Default)]
pub struct Navigator {
    pub current: Navigation,
}

impl Navigator {
    pub fn up(&mut self) {
        match self.current {
            Navigation::Contacts => self.current = Navigation::Conversation,
            Navigation::Conversation => {}
            Navigation::Input => self.current = Navigation::Conversation,
        };
    }

    pub fn down(&mut self) {
        match self.current {
            Navigation::Contacts => self.current = Navigation::Input,
            Navigation::Conversation => self.current = Navigation::Input,
            Navigation::Input => {}
        };
    }

    pub fn left(&mut self) {
        match self.current {
            Navigation::Contacts => {}
            Navigation::Conversation => self.current = Navigation::Contacts,
            Navigation::Input => self.current = Navigation::Contacts,
        };
    }

    pub fn right(&mut self) {
        match self.current {
            Navigation::Contacts => self.current = Navigation::Conversation,
            Navigation::Conversation => {}
            Navigation::Input => {}
        };
    }
}
