//! A document in the ROFF format.
//!
//! [ROFF] is a family of Unix text-formatting languages, implemented
//! by the `nroff`, `troff`, and `groff` programs, among others. See
//! [groff(7)] for a description of the language. This structure is an
//! abstract representation of a document in ROFF format. It is meant
//! for writing code to generate ROFF documents, such as manual pages.
//!
//! # Example
//!
//! ```
//! # use roff::*;
//! let doc = Roff::new().text(vec![roman("hello, world")]).render();
//! assert!(doc.ends_with("hello, world\n"));
//! ```
//!
//! [ROFF]: https://en.wikipedia.org/wiki/Roff_(software)
//! [groff(7)]: https://manpages.debian.org/bullseye/groff/groff.7.en.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(clippy::print_stderr)]
#![warn(clippy::print_stdout)]

use std::io::Write;
use std::write;

/// A ROFF document, consisting of lines.
///
/// Lines are either control lines (requests that are built in, or
/// invocations of macros), or text lines.
///
/// # Example
///
/// ```
/// # use roff::*;
/// let doc = Roff::new()
///     .control("TH", ["FOO", "1"])
///     .control("SH", ["NAME"])
///     .text([roman("foo - do a foo thing")])
///     .render();
/// assert!(doc.ends_with(".TH FOO 1\n.SH NAME\nfoo \\- do a foo thing\n"));
/// ```
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Roff {
    lines: Vec<Line>,
}

impl Roff {
    /// Instantiate a `Roff`
    pub fn new() -> Self {
        Default::default()
    }

    /// Append a control line.
    ///
    /// The line consist of the name of a built-in command or macro,
    /// and some number of arguments. Arguments that contain spaces
    /// will be enclosed with double quotation marks.
    pub fn control<'a>(
        &mut self,
        name: impl Into<String>,
        args: impl IntoIterator<Item = &'a str>,
    ) -> &mut Self {
        self.lines.push(Line::control(
            name.into(),
            args.into_iter().map(|s| s.to_owned()).collect(),
        ));
        self
    }

    /// Append a text line.
    ///
    /// The line will be rendered in a way that ensures it can't be
    /// interpreted as a control line. The caller does not need to
    /// ensure, for example, that the line doesn't start with a
    /// period ("`.`") or an apostrophe ("`'`").
    pub fn text(&mut self, inlines: impl Into<Vec<Inline>>) -> &mut Self {
        self.lines.push(Line::text(inlines.into()));
        self
    }

    /// Render as ROFF source text that can be fed to a ROFF implementation.
    pub fn render(&self) -> String {
        let mut buf = vec![];
        self.to_writer(&mut buf).unwrap(); // writing to a Vec always works
        String::from_utf8(buf)
            .expect("output is utf8 if all input is utf8 and our API guarantees that")
    }

    /// Write to a writer.
    pub fn to_writer(&self, w: &mut dyn Write) -> Result<(), std::io::Error> {
        w.write_all(APOSTROPHE_PREABMLE.as_bytes())?;
        for line in self.lines.iter() {
            line.render(w, Apostrophes::Handle)?;
        }
        Ok(())
    }

    /// Render without handling apostrophes specially.
    ///
    /// You probably want [`render`](Roff::render) or
    /// [`to_writer`](Roff::to_writer) instead of this method.
    ///
    /// Without special handling, apostrophes get typeset as right
    /// single quotes, including in words like "don't". In most
    /// situations, such as in manual pages, that's unwanted. The
    /// other methods handle apostrophes specially to prevent it, but
    /// for completeness, and for testing, this method is provided to
    /// avoid it.
    pub fn to_roff(&self) -> String {
        let mut buf = vec![];
        for line in self.lines.iter() {
            // Writing to a Vec always works, so we discard any error.
            line.render(&mut buf, Apostrophes::DontHandle).unwrap();
        }
        String::from_utf8(buf)
            .expect("output is utf8 if all input is utf8 and our API guarantees that")
    }
}

impl<I: Into<Inline>> From<I> for Roff {
    fn from(other: I) -> Self {
        let mut r = Roff::new();
        r.text([other.into()]);
        r
    }
}

impl<R: Into<Roff>> FromIterator<R> for Roff {
    fn from_iter<I: IntoIterator<Item = R>>(iter: I) -> Self {
        let mut r = Roff::new();
        for i in iter {
            r.lines.extend(i.into().lines);
        }
        r
    }
}

impl<R: Into<Roff>> Extend<R> for Roff {
    fn extend<T: IntoIterator<Item = R>>(&mut self, iter: T) {
        for i in iter {
            self.lines.extend(i.into().lines);
        }
    }
}

/// A part of a text line.
///
/// Text will be escaped for ROFF. No inline escape sequences will be
/// passed to ROFF. The text may contain newlines, but leading periods
/// will be escaped so that they won't be interpreted by ROFF as
/// control lines.
///
/// Note that the strings stored in the variants are stored as they're
/// received from the API user. The `Line::render` function handles
/// escaping etc.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Inline {
    /// Text in the "roman" font, which is the normal font if nothing
    /// else is specified.
    Roman(String),

    /// Text in the italic (slanted) font.
    Italic(String),

    /// Text in a bold face font.
    Bold(String),

    /// A hard line break. This is an inline element so it's easy to
    /// insert a line break in a paragraph.
    LineBreak,
}

/// Turn a string slice into inline text in the roman font.
///
/// This is equivalent to the [roman] function, but may be more
/// convenient to use.
impl<S: Into<String>> From<S> for Inline {
    fn from(s: S) -> Self {
        roman(s)
    }
}

/// Return some inline text in the "roman" font.
///
/// The roman font is the normal font, if no other font is chosen.
pub fn roman(input: impl Into<String>) -> Inline {
    Inline::Roman(input.into())
}

/// Return some inline text in the bold font.
pub fn bold(input: impl Into<String>) -> Inline {
    Inline::Bold(input.into())
}

/// Return some inline text in the italic font.
pub fn italic(input: impl Into<String>) -> Inline {
    Inline::Italic(input.into())
}

/// Return an inline element for a hard line break.
pub fn line_break() -> Inline {
    Inline::LineBreak
}

/// A line in a ROFF document.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum Line {
    /// A control line.
    Control {
        /// Name of control request or macro being invoked.
        name: String,

        /// Arguments on control line.
        args: Vec<String>,
    },

    /// A text line.
    Text(Vec<Inline>),
}

impl Line {
    /// Append a control line.
    pub(crate) fn control(name: String, args: Vec<String>) -> Self {
        Self::Control { name, args }
    }

    /// Append a text line, consisting of inline elements.
    pub(crate) fn text(parts: Vec<Inline>) -> Self {
        Self::Text(parts)
    }

    /// Generate a ROFF line.
    ///
    /// All the ROFF code generation and special handling happens here.
    fn render(
        &self,
        out: &mut dyn Write,
        handle_apostrophes: Apostrophes,
    ) -> Result<(), std::io::Error> {
        match self {
            Self::Control { name, args } => {
                write!(out, ".{name}")?;
                for arg in args {
                    write!(out, " {}", &escape_spaces(arg))?;
                }
            }
            Self::Text(inlines) => {
                let mut at_line_start = true;
                for inline in inlines.iter() {
                    // We need to handle line breaking specially: it
                    // introduces a control line to the ROFF, and the
                    // leading period of that mustn't be escaped.
                    match inline {
                        Inline::LineBreak => {
                            if at_line_start {
                                writeln!(out, ".br")?;
                            } else {
                                writeln!(out, "\n.br")?;
                            }
                        }
                        Inline::Roman(text) | Inline::Italic(text) | Inline::Bold(text) => {
                            let mut text = escape_inline(text);
                            if handle_apostrophes == Apostrophes::Handle {
                                text = escape_apostrophes(&text);
                            };
                            let text = escape_leading_cc(&text);
                            if let Inline::Bold(_) = inline {
                                write!(out, r"\fB{text}\fR")?;
                            } else if let Inline::Italic(_) = inline {
                                write!(out, r"\fI{text}\fR")?;
                            } else {
                                if at_line_start && starts_with_cc(&text) {
                                    // Line would start with a period, so we
                                    // insert a non-printable, zero-width glyph to
                                    // prevent it from being interpreted as such.
                                    // We only do that when it's needed, though,
                                    // to avoid making the output ugly.
                                    //
                                    // Note that this isn't handled by
                                    // escape_leading_cc, as it
                                    // doesn't know when an inline
                                    // element is at the start of a
                                    // line.
                                    write!(out, r"\&").unwrap();
                                }
                                write!(out, "{text}")?;
                            }
                        }
                    }
                    at_line_start = false;
                }
            }
        };
        writeln!(out)?;
        Ok(())
    }
}

/// Does line start with a control character?
fn starts_with_cc(line: &str) -> bool {
    line.starts_with('.') || line.starts_with('\'')
}

/// This quotes strings with spaces. This doesn't handle strings with
/// quotes in any way: there doesn't seem to a way to escape them.
fn escape_spaces(w: &str) -> String {
    if w.contains(' ') {
        format!("\"{w}\"")
    } else {
        w.to_owned()
    }
}

/// Prevent leading periods or apostrophes on lines to be interpreted
/// as control lines. Note that this needs to be done for apostrophes
/// whether they need special handling for typesetting or not: a
/// leading apostrophe on a line indicates a control line.
fn escape_leading_cc(s: &str) -> String {
    s.replace("\n.", "\n\\&.").replace("\n'", "\n\\&'")
}

/// Escape anything that may be interpreted by the roff processor in a
/// text line: dashes and backslashes are escaped with a backslash.
/// Apostrophes are not handled.
fn escape_inline(text: &str) -> String {
    text.replace('\\', r"\\").replace('-', r"\-")
}

/// Handle apostrophes.
fn escape_apostrophes(text: &str) -> String {
    text.replace('\'', APOSTROPHE)
}

#[derive(Eq, PartialEq)]
enum Apostrophes {
    Handle,
    DontHandle,
}

/// Use the apostrophe string variable.
const APOSTROPHE: &str = r"\*(Aq";

/// A preamble added to the start of rendered output.
///
/// This defines a string variable that contains an apostrophe. For
/// historical reasons, there seems to be no other portable way to
/// represent apostrophes across various implementations of the ROFF
/// language. In implementations that produce output like `PostScript`
/// or PDF, an apostrophe gets typeset as a right single quote, which
/// looks different from an apostrophe. For terminal output ("ASCII"),
/// such as when using nroff, an apostrophe looks indistinguishable
/// from a right single quote. For manual pages, and similar content,
/// an apostrophe is more generally desired than the right single
/// quote, so we convert all apostrophe characters in input text into
/// a use of the string variable defined in the preamble.
///
/// The special handling of apostrophes is avoided in the
/// [`to_roff`](Roff::to_roff) method, but it's used in the
/// [`render`](Roff::render) and [`to_writer`](Roff::to_writer)
/// methods.
///
/// See: <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=507673#65>
const APOSTROPHE_PREABMLE: &str = r#".ie \n(.g .ds Aq \(aq
.el .ds Aq '
"#;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn escape_dash() {
        assert_eq!(r"\-", escape_inline("-"));
    }

    #[test]
    fn escape_backslash() {
        assert_eq!(r"\\x", escape_inline(r"\x"));
    }

    #[test]
    fn escape_backslash_and_dash() {
        assert_eq!(r"\\\-", escape_inline(r"\-"));
    }

    #[test]
    fn escapes_leading_control_chars() {
        assert_eq!("foo\n\\&.bar\n\\&'yo", escape_leading_cc("foo\n.bar\n'yo"));
    }

    #[test]
    fn escape_plain() {
        assert_eq!("abc", escape_inline("abc"));
    }

    #[test]
    fn render_roman() {
        let text = Roff::new().text([roman("foo")]).to_roff();
        assert_eq!(text, "foo\n");
    }

    #[test]
    fn render_dash() {
        let text = Roff::new().text([roman("foo-bar")]).to_roff();
        assert_eq!(text, "foo\\-bar\n");
    }

    #[test]
    fn render_italic() {
        let text = Roff::new().text([italic("foo")]).to_roff();
        assert_eq!(text, "\\fIfoo\\fR\n");
    }

    #[test]
    fn render_bold() {
        let text = Roff::new().text([bold("foo")]).to_roff();
        assert_eq!(text, "\\fBfoo\\fR\n");
    }

    #[test]
    fn render_text() {
        let text = Roff::new().text([roman("roman")]).to_roff();
        assert_eq!(text, "roman\n");
    }

    #[test]
    fn render_text_with_leading_period() {
        let text = Roff::new().text([roman(".roman")]).to_roff();
        assert_eq!(text, "\\&.roman\n");
    }

    #[test]
    fn render_text_with_newline_period() {
        let text = Roff::new().text([roman("foo\n.roman")]).to_roff();
        assert_eq!(text, "foo\n\\&.roman\n");
    }
    #[test]
    fn render_line_break() {
        let text = Roff::new()
            .text([roman("roman"), Inline::LineBreak, roman("more")])
            .to_roff();
        assert_eq!(text, "roman\n.br\nmore\n");
    }

    #[test]
    fn render_control() {
        let text = Roff::new().control("foo", ["bar", "foo and bar"]).to_roff();
        assert_eq!(text, ".foo bar \"foo and bar\"\n");
    }
}

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
