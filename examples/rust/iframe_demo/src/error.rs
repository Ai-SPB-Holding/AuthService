#[derive(Debug)]
pub enum DemoError {
    Msg(String),
}

impl DemoError {
    pub fn msg(s: impl Into<String>) -> Self {
        DemoError::Msg(s.into())
    }
}

impl std::fmt::Display for DemoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoError::Msg(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for DemoError {}

impl From<String> for DemoError {
    fn from(s: String) -> Self {
        DemoError::Msg(s)
    }
}
