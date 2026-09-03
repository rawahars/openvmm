// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::Component;
use std::path::Path;
use thiserror::Error;

pub(crate) const MAX_EXTENTS: usize = 512;

const DESCRIPTOR_HEADER: &str = "# Disk DescriptorFile";
const EXTENT_MARKER: &str = "# Extent description";

#[derive(Debug)]
pub(crate) struct ParsedDescriptor {
    pub extents: Vec<ParsedExtent>,
}

#[derive(Debug)]
pub(crate) struct ParsedExtent {
    pub path: String,
    pub sector_count: u64,
    pub file_offset: u64,
}

#[derive(Clone, Copy, Debug)]
enum CreateType {
    MonolithicFlat,
    TwoGbMaxExtentFlat,
}

/// An error in a VMDK descriptor.
#[derive(Debug, Error)]
pub enum ParseError {
    /// The descriptor is not UTF-8 text.
    #[error("VMDK descriptor is not valid UTF-8")]
    InvalidEncoding,
    /// A required descriptor field is missing.
    #[error("VMDK descriptor is missing required field '{0}'")]
    MissingField(&'static str),
    /// A descriptor line is invalid or unsupported.
    #[error("invalid VMDK descriptor at line {line}: {message}")]
    Invalid {
        /// One-based line number.
        line: usize,
        /// Description of the invalid content.
        message: String,
    },
    /// The descriptor contains more extents than this backend accepts.
    #[error("VMDK descriptor has more than {MAX_EXTENTS} extents")]
    TooManyExtents,
}

pub(crate) fn parse_descriptor(bytes: &[u8]) -> Result<ParsedDescriptor, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidEncoding)?;
    if text.contains('\0') {
        return Err(invalid(1, "NUL bytes are not allowed"));
    }

    let mut lines = text.lines().enumerate();
    let Some((_, first_line)) = lines.next() else {
        return Err(ParseError::MissingField(DESCRIPTOR_HEADER));
    };
    if first_line.trim_end() != DESCRIPTOR_HEADER {
        return Err(invalid(1, format!("expected '{DESCRIPTOR_HEADER}'")));
    }

    let mut saw_version = false;
    let mut saw_parent_cid = false;
    let mut create_type = None;
    let mut saw_extent_marker = false;

    for (index, line) in lines.by_ref() {
        let line_number = index + 1;
        let line = line.trim();
        if line == EXTENT_MARKER {
            saw_extent_marker = true;
            break;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(invalid(line_number, "expected a key/value field"));
        };
        let key = key.trim();
        match key {
            "version" => {
                set_once(&mut saw_version, line_number, key)?;
                if scalar(value, line_number)? != "1" {
                    return Err(invalid(
                        line_number,
                        "only descriptor version 1 is supported",
                    ));
                }
            }
            "createType" => {
                if create_type.is_some() {
                    return Err(invalid(line_number, "duplicate 'createType' field"));
                }
                create_type = Some(match scalar(value, line_number)? {
                    "monolithicFlat" => CreateType::MonolithicFlat,
                    "twoGbMaxExtentFlat" => CreateType::TwoGbMaxExtentFlat,
                    value => {
                        return Err(invalid(
                            line_number,
                            format!("unsupported createType '{value}'"),
                        ));
                    }
                });
            }
            "parentCID" => {
                set_once(&mut saw_parent_cid, line_number, key)?;
                if !scalar(value, line_number)?.eq_ignore_ascii_case("ffffffff") {
                    return Err(invalid(line_number, "parent VMDK disks are not supported"));
                }
            }
            "parentFileNameHint" => {
                return Err(invalid(line_number, "parent VMDK disks are not supported"));
            }
            "encoding" => {
                if !scalar(value, line_number)?.eq_ignore_ascii_case("UTF-8") {
                    return Err(invalid(line_number, "only UTF-8 encoding is supported"));
                }
            }
            _ => {}
        }
    }

    if !saw_version {
        return Err(ParseError::MissingField("version"));
    }
    let create_type = create_type.ok_or(ParseError::MissingField("createType"))?;
    if !saw_extent_marker {
        return Err(ParseError::MissingField(EXTENT_MARKER));
    }

    let mut extents = Vec::new();
    let mut last_extent_line = 1;
    for (index, line) in lines {
        let line_number = index + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if is_ddb_marker(line) || is_ddb_entry(line) {
            break;
        }
        if line.starts_with('#') {
            continue;
        }
        if extents.len() == MAX_EXTENTS {
            return Err(ParseError::TooManyExtents);
        }
        extents.push(parse_extent(line, line_number)?);
        last_extent_line = line_number;
    }

    if extents.is_empty() {
        return Err(ParseError::MissingField("FLAT extent"));
    }
    if matches!(create_type, CreateType::MonolithicFlat) && extents.len() != 1 {
        return Err(invalid(
            last_extent_line,
            "monolithicFlat descriptors must contain exactly one extent",
        ));
    }

    Ok(ParsedDescriptor { extents })
}

fn parse_extent(line: &str, line_number: usize) -> Result<ParsedExtent, ParseError> {
    let mut cursor = 0;
    let access = next_token(line, &mut cursor)
        .ok_or_else(|| invalid(line_number, "missing extent access mode"))?;
    if access != "RW" && access != "RDONLY" {
        return Err(invalid(
            line_number,
            format!("unsupported extent access mode '{access}'"),
        ));
    }

    let sector_count = parse_decimal(
        next_token(line, &mut cursor)
            .ok_or_else(|| invalid(line_number, "missing extent sector count"))?,
        line_number,
        "sector count",
    )?;
    if sector_count == 0 {
        return Err(invalid(line_number, "extent sector count must be nonzero"));
    }

    let extent_type =
        next_token(line, &mut cursor).ok_or_else(|| invalid(line_number, "missing extent type"))?;
    if extent_type != "FLAT" {
        return Err(invalid(
            line_number,
            format!("unsupported extent type '{extent_type}'"),
        ));
    }

    skip_whitespace(line, &mut cursor);
    let bytes = line.as_bytes();
    if bytes.get(cursor) != Some(&b'"') {
        return Err(invalid(line_number, "extent path must be quoted"));
    }
    cursor += 1;
    let path_start = cursor;
    while bytes.get(cursor).is_some_and(|byte| *byte != b'"') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return Err(invalid(line_number, "unterminated extent path"));
    }
    let path = &line[path_start..cursor];
    cursor += 1;
    validate_path(path, line_number)?;

    let file_offset = match next_token(line, &mut cursor) {
        Some(value) => parse_decimal(value, line_number, "file offset")?,
        None => 0,
    };
    if next_token(line, &mut cursor).is_some() {
        return Err(invalid(line_number, "unexpected trailing extent fields"));
    }

    Ok(ParsedExtent {
        path: path.to_owned(),
        sector_count,
        file_offset,
    })
}

fn scalar(value: &str, line_number: usize) -> Result<&str, ParseError> {
    let value = value.trim();
    if let Some(value) = value.strip_prefix('"') {
        let Some(value) = value.strip_suffix('"') else {
            return Err(invalid(line_number, "unterminated quoted value"));
        };
        if value.contains('"') {
            return Err(invalid(line_number, "unexpected quote in value"));
        }
        Ok(value)
    } else if value.is_empty() || value.chars().any(char::is_whitespace) {
        Err(invalid(line_number, "invalid unquoted value"))
    } else {
        Ok(value)
    }
}

fn parse_decimal(value: &str, line_number: usize, field: &str) -> Result<u64, ParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(
            line_number,
            format!("{field} must be an unsigned decimal integer"),
        ));
    }
    value
        .parse()
        .map_err(|_| invalid(line_number, format!("{field} is too large")))
}

fn validate_path(path: &str, line_number: usize) -> Result<(), ParseError> {
    if path.is_empty() || path.chars().any(char::is_control) {
        return Err(invalid(line_number, "invalid extent path"));
    }
    if path
        .split(['/', '\\'])
        .any(|component| component == "." || component == "..")
        || Path::new(path)
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid(
            line_number,
            "'.' and '..' path components are not supported",
        ));
    }
    Ok(())
}

fn next_token<'a>(line: &'a str, cursor: &mut usize) -> Option<&'a str> {
    skip_whitespace(line, cursor);
    let start = *cursor;
    let bytes = line.as_bytes();
    while bytes
        .get(*cursor)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        *cursor += 1;
    }
    (start != *cursor).then(|| &line[start..*cursor])
}

fn skip_whitespace(line: &str, cursor: &mut usize) {
    let bytes = line.as_bytes();
    while bytes
        .get(*cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        *cursor += 1;
    }
}

fn set_once(seen: &mut bool, line_number: usize, field: &str) -> Result<(), ParseError> {
    if std::mem::replace(seen, true) {
        return Err(invalid(line_number, format!("duplicate '{field}' field")));
    }
    Ok(())
}

fn is_ddb_marker(line: &str) -> bool {
    line.eq_ignore_ascii_case("# The Disk Data Base") || line.eq_ignore_ascii_case("#DDB")
}

fn is_ddb_entry(line: &str) -> bool {
    line.as_bytes()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"ddb."))
}

fn invalid(line: usize, message: impl Into<String>) -> ParseError {
    ParseError::Invalid {
        line,
        message: message.into(),
    }
}
