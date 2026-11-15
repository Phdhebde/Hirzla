//! A strict CSV reader (RFC 4180, plus the `;` and tab separators of spreadsheet exports),
//! written here so that every cell lands in an erasing buffer: an imported file is full of
//! passwords. Each cell is allocated once, at its final size, so no growing buffer leaves an
//! unerased copy behind.
//!
//! Accepted: an optional UTF-8 byte order mark, `\n` or `\r\n` line ends, quoted cells with
//! doubled quotes and line breaks inside, empty lines (skipped). Refused: a quote inside an
//! unquoted cell, text after a closing quote, an unterminated quote, too many rows, columns
//! or bytes in a cell.

use zeroize::Zeroizing;

/// Most data rows read from one file.
pub const MAX_ROWS: usize = 100_000;
/// Most columns in a row.
pub const MAX_COLUMNS: usize = 64;
/// Longest cell, in bytes (the core's limit for a text field).
pub const MAX_CELL: usize = hirzla_core::proto::MAX_TEXT;

/// A row: its line number in the file (from 1) and its cells.
pub struct Row {
    /// Line where the row starts.
    pub line: usize,
    /// Cells, in erasing buffers.
    pub cells: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the content: cells may be secret.
        write!(f, "Row(line {}, {} cells)", self.line, self.cells.len())
    }
}

/// Why a file was refused. The line is given, never the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CsvError {
    /// A quote opens and never closes.
    #[error("unterminated quote (line {0})")]
    UnterminatedQuote(usize),
    /// A quote in the middle of an unquoted cell, or text after a closing quote.
    #[error("misplaced quote (line {0})")]
    StrayQuote(usize),
    /// Too many rows.
    #[error("too many rows")]
    TooManyRows,
    /// Too many columns (line).
    #[error("too many columns (line {0})")]
    TooManyColumns(usize),
    /// A cell is too long (line).
    #[error("cell too long (line {0})")]
    CellTooLong(usize),
    /// No header row.
    #[error("empty file")]
    Empty,
}

/// The separator of the file, guessed from its first line: the most frequent of `,`, `;`
/// and tab outside quotes (`,` when none appears).
#[must_use]
pub fn guess_separator(text: &str) -> char {
    let mut counts = [(',', 0usize), (';', 0), ('\t', 0)];
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '"' => quoted = !quoted,
            '\n' if !quoted => break,
            _ if !quoted => {
                for (sep, n) in &mut counts {
                    if c == *sep {
                        *n += 1;
                    }
                }
            }
            _ => {}
        }
    }
    let mut best = counts[0];
    for c in counts {
        if c.1 > best.1 {
            best = c;
        }
    }
    best.0
}

/// Copies a cell into an erasing string allocated at its final size, undoubling quotes.
fn cell(raw: &str, quoted: bool) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(raw.len()));
    if quoted {
        let mut chars = raw.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '"' && chars.peek() == Some(&'"') {
                chars.next();
            }
            s.push(c);
        }
    } else {
        s.push_str(raw);
    }
    s
}

/// Reads every row of `text` with separator `sep`. The first row is the header.
///
/// # Errors
/// [`CsvError`].
pub fn parse(text: &str, sep: char) -> Result<Vec<Row>, CsvError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let bytes = text.as_bytes();
    let sep = sep as u8;
    let mut rows = Vec::new();
    let mut cells: Vec<Zeroizing<String>> = Vec::new();
    let mut line = 1usize;
    let mut row_line = 1usize;
    let mut i = 0usize;
    // `sep`, `"`, `\r` and `\n` are ASCII: byte indices found by scanning for them are
    // always on character boundaries of the UTF-8 text.
    loop {
        // Start of a cell.
        let (value, end) = if bytes.get(i) == Some(&b'"') {
            let start = i + 1;
            let mut j = start;
            loop {
                match bytes.get(j) {
                    None => return Err(CsvError::UnterminatedQuote(row_line)),
                    Some(b'"') if bytes.get(j + 1) == Some(&b'"') => j += 2,
                    Some(b'"') => break,
                    Some(b'\n') => {
                        line += 1;
                        j += 1;
                    }
                    Some(_) => j += 1,
                }
            }
            if j - start > MAX_CELL {
                return Err(CsvError::CellTooLong(row_line));
            }
            let value = cell(&text[start..j], true);
            (value, j + 1)
        } else {
            let start = i;
            let mut j = start;
            while let Some(&b) = bytes.get(j) {
                if b == sep || b == b'\n' || b == b'\r' {
                    break;
                }
                if b == b'"' {
                    return Err(CsvError::StrayQuote(row_line));
                }
                j += 1;
            }
            if j - start > MAX_CELL {
                return Err(CsvError::CellTooLong(row_line));
            }
            (cell(&text[start..j], false), j)
        };
        if cells.len() == MAX_COLUMNS {
            return Err(CsvError::TooManyColumns(row_line));
        }
        cells.push(value);
        // After a cell: separator, end of line or end of text.
        match bytes.get(end) {
            Some(&b) if b == sep => i = end + 1,
            Some(b'\r') if bytes.get(end + 1) == Some(&b'\n') => {
                i = end + 2;
                finish_row(&mut rows, &mut cells, row_line)?;
                line += 1;
                row_line = line;
            }
            Some(b'\n' | b'\r') => {
                i = end + 1;
                finish_row(&mut rows, &mut cells, row_line)?;
                line += 1;
                row_line = line;
            }
            None => {
                finish_row(&mut rows, &mut cells, row_line)?;
                break;
            }
            Some(_) => return Err(CsvError::StrayQuote(row_line)),
        }
        if i >= bytes.len() {
            break;
        }
    }
    if rows.is_empty() {
        return Err(CsvError::Empty);
    }
    Ok(rows)
}

fn finish_row(
    rows: &mut Vec<Row>,
    cells: &mut Vec<Zeroizing<String>>,
    line: usize,
) -> Result<(), CsvError> {
    let cells = std::mem::take(cells);
    // An empty line is one empty cell: skip it.
    if cells.len() == 1 && cells[0].is_empty() {
        return Ok(());
    }
    if rows.len() > MAX_ROWS {
        return Err(CsvError::TooManyRows);
    }
    rows.push(Row { line, cells });
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn texts(rows: &[Row]) -> Vec<Vec<String>> {
        rows.iter()
            .map(|r| r.cells.iter().map(|c| c.as_str().to_owned()).collect())
            .collect()
    }

    #[test]
    fn plain_rows() {
        let rows = parse("a,b,c\n1,2,3\n", ',').unwrap();
        assert_eq!(texts(&rows), [["a", "b", "c"], ["1", "2", "3"]]);
        assert_eq!(rows[1].line, 2);
    }

    #[test]
    fn quotes_doubled_quotes_and_line_breaks() {
        let rows = parse(
            "\u{feff}t,n\r\n\"a,b\",\"il dit \"\"oui\"\"\"\r\n\"x\",\"l1\nl2\"\nfin,\n",
            ',',
        )
        .unwrap();
        assert_eq!(
            texts(&rows),
            [
                vec!["t", "n"],
                vec!["a,b", "il dit \"oui\""],
                vec!["x", "l1\nl2"],
                vec!["fin", ""],
            ]
        );
        // The row after the multi-line cell starts on line 5.
        assert_eq!(rows[3].line, 5);
    }

    #[test]
    fn empty_lines_are_skipped_and_no_final_newline_is_fine() {
        let rows = parse("a;b\n\n1;2", ';').unwrap();
        assert_eq!(texts(&rows), [["a", "b"], ["1", "2"]]);
    }

    #[test]
    fn non_ascii_text_is_kept() {
        let rows = parse("titre;mot de passe\nBanque é;pässwörd€\n", ';').unwrap();
        assert_eq!(texts(&rows)[1], ["Banque é", "pässwörd€"]);
    }

    #[test]
    fn separator_is_guessed_from_the_header() {
        assert_eq!(guess_separator("a,b,c\n"), ',');
        assert_eq!(guess_separator("a;b;c\n1,2;3"), ';');
        assert_eq!(guess_separator("a\tb\tc"), '\t');
        assert_eq!(guess_separator("\"a;b\",c\n"), ',');
        assert_eq!(guess_separator("seul\n"), ',');
    }

    #[test]
    fn unterminated_quote_is_refused() {
        assert_eq!(
            parse("a,b\n\"x,y\n", ',').unwrap_err(),
            CsvError::UnterminatedQuote(2)
        );
    }

    #[test]
    fn stray_quotes_are_refused() {
        assert_eq!(
            parse("a,b\nx\"y,z\n", ',').unwrap_err(),
            CsvError::StrayQuote(2)
        );
        assert_eq!(
            parse("a,b\n\"x\"y,z\n", ',').unwrap_err(),
            CsvError::StrayQuote(2)
        );
    }

    #[test]
    fn too_many_columns_is_refused() {
        let header = vec!["c"; MAX_COLUMNS + 1].join(",");
        assert_eq!(
            parse(&header, ',').unwrap_err(),
            CsvError::TooManyColumns(1)
        );
    }

    #[test]
    fn too_long_cell_is_refused() {
        let text = format!("a\n{}\n", "x".repeat(MAX_CELL + 1));
        assert_eq!(parse(&text, ',').unwrap_err(), CsvError::CellTooLong(2));
        let text = format!("a\n\"{}\"\n", "x".repeat(MAX_CELL + 1));
        assert_eq!(parse(&text, ',').unwrap_err(), CsvError::CellTooLong(2));
    }

    #[test]
    fn empty_file_is_refused() {
        assert_eq!(parse("", ',').unwrap_err(), CsvError::Empty);
        assert_eq!(parse("\u{feff}\n\n", ',').unwrap_err(), CsvError::Empty);
    }

    #[test]
    fn debug_shows_no_content() {
        let rows = parse("a\nmot-de-passe-secret\n", ',').unwrap();
        let shown = format!("{:?}", rows[1]);
        assert!(!shown.contains("secret"), "{shown}");
    }
}
