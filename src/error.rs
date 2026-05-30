use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ErrorDetail {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
}

impl ErrorDetail {
    pub const fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            field: None,
            index: None,
        }
    }

    pub fn field(mut self, field: &str) -> Self {
        self.field = Some(field.to_owned());
        self
    }

    pub fn indexed_field(mut self, field: &str, index: usize) -> Self {
        self.field = Some(field.to_owned());
        self.index = Some(index);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_bounded_field_context() {
        let field = ErrorDetail::new("invalid", "invalid").field("mode");
        let indexed =
            ErrorDetail::new("invalid", "invalid").indexed_field("allowlist.destination", 2);

        assert_eq!(field.field.as_deref(), Some("mode"));
        assert_eq!(field.index, None);
        assert_eq!(indexed.field.as_deref(), Some("allowlist.destination"));
        assert_eq!(indexed.index, Some(2));
    }
}
