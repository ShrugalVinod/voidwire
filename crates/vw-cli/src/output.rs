//! Terminal output: colors, tables and the output sink used by commands.
//!
//! Colors are emitted only when `anstream` decides the stream supports them
//! (TTY, `NO_COLOR` unset, `CLICOLOR_FORCE` honoured); on Windows `anstream`
//! also translates ANSI sequences for legacy consoles.

use std::io::Write;

/// Text roles; each maps to one ANSI SGR sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Plain,
    Bold,
    Dim,
    Ok,
    Bad,
    Warn,
    Accent,
}

impl Style {
    const fn sgr(self) -> &'static str {
        match self {
            Style::Plain => "",
            Style::Bold => "1",
            Style::Dim => "2",
            Style::Ok => "1;32",
            Style::Bad => "1;31",
            Style::Warn => "33",
            Style::Accent => "36",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Theme {
    pub color: bool,
}

impl Theme {
    pub const PLAIN: Theme = Theme { color: false };
    pub const COLOR: Theme = Theme { color: true };

    pub fn paint(&self, style: Style, text: &str) -> String {
        if !self.color || style == Style::Plain || text.is_empty() {
            text.to_string()
        } else {
            format!("\x1b[{}m{text}\x1b[0m", style.sgr())
        }
    }

    pub fn ok(&self, t: &str) -> String {
        self.paint(Style::Ok, t)
    }
    pub fn bad(&self, t: &str) -> String {
        self.paint(Style::Bad, t)
    }
    pub fn warn(&self, t: &str) -> String {
        self.paint(Style::Warn, t)
    }
    pub fn accent(&self, t: &str) -> String {
        self.paint(Style::Accent, t)
    }
    pub fn dim(&self, t: &str) -> String {
        self.paint(Style::Dim, t)
    }
    pub fn bold(&self, t: &str) -> String {
        self.paint(Style::Bold, t)
    }
}

/// Visible width of plain text (ANSI-free), counting chars.
pub fn width(s: &str) -> usize {
    s.chars().count()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub text: String,
    pub style: Style,
}

impl Cell {
    pub fn new(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }
    pub fn plain(text: impl Into<String>) -> Self {
        Self::new(text, Style::Plain)
    }
}

/// Left-aligned table with a header row; padding ignores color codes.
#[derive(Debug, Clone, Default)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<Cell>>,
    indent: usize,
}

impl Table {
    pub fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
            indent: 0,
        }
    }

    pub fn indent(mut self, n: usize) -> Self {
        self.indent = n;
        self
    }

    pub fn row(&mut self, cells: Vec<Cell>) {
        self.rows.push(cells);
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn render(&self, theme: &Theme) -> String {
        let cols = self
            .rows
            .iter()
            .map(Vec::len)
            .chain(std::iter::once(self.headers.len()))
            .max()
            .unwrap_or(0);
        let mut widths = vec![0usize; cols];
        for (i, h) in self.headers.iter().enumerate() {
            widths[i] = widths[i].max(width(h));
        }
        for r in &self.rows {
            for (i, c) in r.iter().enumerate() {
                widths[i] = widths[i].max(width(&c.text));
            }
        }
        let pad = " ".repeat(self.indent);
        let mut out = String::new();
        let line = |cells: &[(String, usize)], out: &mut String| {
            out.push_str(&pad);
            let n = cells.len();
            for (i, (painted, w)) in cells.iter().enumerate() {
                out.push_str(painted);
                if i + 1 < n {
                    out.push_str(&" ".repeat(widths[i] - w + 2));
                }
            }
            out.push('\n');
        };
        if !self.headers.is_empty() {
            let cells: Vec<(String, usize)> = self
                .headers
                .iter()
                .map(|h| (theme.dim(h), width(h)))
                .collect();
            line(&cells, &mut out);
        }
        for r in &self.rows {
            let cells: Vec<(String, usize)> = r
                .iter()
                .map(|c| (theme.paint(c.style, &c.text), width(&c.text)))
                .collect();
            line(&cells, &mut out);
        }
        out
    }
}

/// Where commands write. Results go to `out`; progress notes, prompts and
/// errors go to `err` so piping stdout stays clean.
pub struct Out {
    out: Box<dyn Write + Send>,
    err: Box<dyn Write + Send>,
    pub theme: Theme,
    pub json: bool,
}

impl Out {
    pub fn new(
        out: Box<dyn Write + Send>,
        err: Box<dyn Write + Send>,
        theme: Theme,
        json: bool,
    ) -> Self {
        Self {
            out,
            err,
            theme,
            json,
        }
    }

    /// Real stdout/stderr with automatic color detection.
    pub fn terminal(json: bool) -> Self {
        let color = !json
            && anstream::AutoStream::choice(&std::io::stdout()) != anstream::ColorChoice::Never;
        Self::new(
            Box::new(anstream::stdout()),
            Box::new(anstream::stderr()),
            Theme { color },
            json,
        )
    }

    /// Write text as-is (no trailing newline added).
    pub fn print(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    pub fn line(&mut self, s: &str) {
        let _ = writeln!(self.out, "{s}");
        let _ = self.out.flush();
    }

    pub fn note(&mut self, s: &str) {
        let _ = writeln!(self.err, "{s}");
        let _ = self.err.flush();
    }

    pub fn emit_json(&mut self, v: &serde_json::Value) {
        let text = serde_json::to_string_pretty(v).unwrap_or_else(|_| "null".into());
        self.line(&text);
    }

    /// Serialize any value as pretty JSON on stdout.
    pub fn emit<T: serde::Serialize>(&mut self, v: &T) {
        match serde_json::to_value(v) {
            Ok(j) => self.emit_json(&j),
            Err(e) => self.note(&format!("cannot serialize output: {e}")),
        }
    }

    /// Report a failure on the right stream in the right format.
    pub fn error(&mut self, e: &crate::exit::CliError) {
        if self.json {
            self.emit_json(&e.json());
            return;
        }
        let t = self.theme;
        self.note(&format!("{} {}", t.bad("error:"), e.message));
        if let Some(h) = &e.hint {
            self.note(&format!("{} {h}", t.warn("hint:")));
        }
    }
}
