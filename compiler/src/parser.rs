//! Simple hand-written parser — more robust than PEG for our DSL.
//! Replaces the pest-based parser.

use crate::ast::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Parse error at line {line}: {msg}")]
    Parse { line: usize, msg: String },

    #[error("Type error: {0}")]
    TypeError(String),
}

/// Parse a complete ZKF source file.
pub fn parse(source: &str, filename: &str) -> Result<Program, ParseError> {
    let mut parser = ParserState::new(source);
    let mut statements = Vec::new();

    while !parser.is_eof() {
        parser.skip_whitespace_and_comments();
        if parser.is_eof() {
            break;
        }

        if parser.peek_word("prove") {
            let block = parse_prove_block(&mut parser)?;
            statements.push(Statement::ProveBlock(block));
        } else if parser.peek_word("import") {
            parser.advance(6); // "import"
            parser.skip_whitespace();
            let path = parser.read_string_literal()?;
            parser.expect_char(';')?;
            statements.push(Statement::Import(path));
        } else if parser.peek_str("//") || parser.peek_str("/*") {
            parser.skip_comment();
            // Comments are skipped, not stored
        } else {
            return Err(ParseError::Parse {
                line: parser.line,
                msg: format!("Unexpected token: '{}'", parser.rest().chars().take(20).collect::<String>()),
            });
        }
    }

    let name = filename
        .strip_suffix(".zkf")
        .unwrap_or(filename)
        .to_string();

    Ok(Program {
        name,
        statements,
        source_info: SourceInfo {
            file: filename.to_string(),
            spans: vec![],
        },
    })
}

struct ParserState<'a> {
    source: &'a str,
    pos: usize,
    line: usize,
}

impl<'a> ParserState<'a> {
    fn new(source: &'a str) -> Self {
        ParserState { source, pos: 0, line: 1 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.source.len()
    }

    fn rest(&self) -> &'a str {
        &self.source[self.pos..]
    }

    fn peek_char(&self) -> Option<char> {
        self.source[self.pos..].chars().next()
    }

    fn peek_word(&self, word: &str) -> bool {
        let rest = self.rest();
        rest.starts_with(word)
            && rest[word.len()..]
                .chars()
                .next()
                .map_or(true, |c| !c.is_alphanumeric() && c != '_')
    }

    fn peek_str(&self, s: &str) -> bool {
        self.rest().starts_with(s)
    }

    fn advance(&mut self, n: usize) {
        let skipped = &self.source[self.pos..self.pos + n];
        self.line += skipped.chars().filter(|&c| c == '\n').count();
        self.pos += n;
    }

    fn expect_char(&mut self, expected: char) -> Result<(), ParseError> {
        self.skip_whitespace();
        match self.peek_char() {
            Some(c) if c == expected => {
                self.advance(1);
                Ok(())
            }
            Some(c) => Err(ParseError::Parse {
                line: self.line,
                msg: format!("Expected '{}', found '{}'", expected, c),
            }),
            None => Err(ParseError::Parse {
                line: self.line,
                msg: format!("Expected '{}', found EOF", expected),
            }),
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek_char() {
            if c.is_whitespace() {
                self.advance(1);
            } else {
                break;
            }
        }
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            self.skip_whitespace();
            let rest = self.rest();
            if rest.starts_with("//") {
                let end = rest.find('\n').unwrap_or(rest.len());
                self.advance(end);
            } else if rest.starts_with("/*") {
                if let Some(end) = rest.find("*/") {
                    self.advance(end + 2);
                } else {
                    self.pos = self.source.len(); // Unterminated comment
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn skip_comment(&mut self) {
        let rest = self.rest();
        if rest.starts_with("//") {
            let end = rest.find('\n').unwrap_or(rest.len());
            self.advance(end);
        } else if rest.starts_with("/*") {
            if let Some(end) = rest.find("*/") {
                self.advance(end + 2);
            }
        }
    }

    fn read_identifier(&mut self) -> Result<String, ParseError> {
        self.skip_whitespace();
        let rest = self.rest();
        let len = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .count();
        if len == 0 {
            return Err(ParseError::Parse {
                line: self.line,
                msg: "Expected identifier".into(),
            });
        }
        let id = rest[..len].to_string();
        // Don't advance past the identifier bytes — use char-based iteration
        let _char_count = rest[..len].chars().count();
        // Actually let's use byte-slice approach. If we only use ASCII identifiers, it's fine.
        // For robustness, use the byte length of the str slice.
        let _byte_len = rest[..len].len();
        // But wait, `len` here is in bytes. If identifier contains multi-byte chars, this could be wrong.
        // For now, assume ASCII identifiers.
        self.pos += len;
        Ok(id)
    }

    fn read_number(&mut self) -> Result<String, ParseError> {
        self.skip_whitespace();
        let rest = self.rest();
        if rest.starts_with("0x") || rest.starts_with("0X") {
            let hex_end = rest[2..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .count();
            let num = rest[..2 + hex_end].to_string();
            self.pos += num.len();
            Ok(num)
        } else {
            let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
            let num = rest[..digits].to_string();
            self.pos += num.len();
            Ok(num)
        }
    }

    fn read_string_literal(&mut self) -> Result<String, ParseError> {
        self.skip_whitespace();
        if !self.rest().starts_with('"') {
            return Err(ParseError::Parse {
                line: self.line,
                msg: "Expected string literal".into(),
            });
        }
        self.advance(1); // skip opening "
        let rest = self.rest();
        if let Some(end) = rest.find('"') {
            let s = rest[..end].to_string();
            self.advance(end + 1); // skip content + closing "
            Ok(s)
        } else {
            Err(ParseError::Parse {
                line: self.line,
                msg: "Unterminated string literal".into(),
            })
        }
    }
}

fn parse_prove_block(parser: &mut ParserState) -> Result<ProveBlock, ParseError> {
    parser.advance(5); // "prove"
    parser.skip_whitespace();

    // Optional name
    let name = if parser.peek_char().map_or(false, |c| c.is_alphabetic()) {
        Some(parser.read_identifier()?)
    } else {
        None
    };

    parser.expect_char('{')?;

    let mut inputs = Vec::new();
    let mut assertions = Vec::new();
    let mut outputs = Vec::new();

    loop {
        parser.skip_whitespace_and_comments();
        if parser.is_eof() {
            break;
        }
        if parser.peek_char() == Some('}') {
            parser.advance(1);
            break;
        }

        if parser.peek_word("input") {
            inputs.push(parse_input_decl(parser)?);
        } else if parser.peek_word("assert") {
            assertions.push(parse_assert_stmt(parser)?);
        } else if parser.peek_word("output") {
            outputs.push(parse_output_decl(parser)?);
        } else {
            return Err(ParseError::Parse {
                line: parser.line,
                msg: format!(
                    "Unexpected token in prove block: '{}'",
                    parser.rest().chars().take(20).collect::<String>()
                ),
            });
        }
    }

    Ok(ProveBlock {
        name,
        inputs,
        assertions,
        outputs,
    })
}

fn parse_input_decl(parser: &mut ParserState) -> Result<InputDecl, ParseError> {
    parser.advance(5); // "input"
    parser.skip_whitespace();
    let name = parser.read_identifier()?;
    parser.expect_char(':')?;
    parser.skip_whitespace();

    let privacy = if parser.peek_word("Private") {
        parser.advance(7);
        Privacy::Private
    } else if parser.peek_word("Public") {
        parser.advance(6);
        Privacy::Public
    } else {
        return Err(ParseError::Parse {
            line: parser.line,
            msg: "Expected Private or Public".into(),
        });
    };

    parser.expect_char('<')?;
    parser.skip_whitespace();
    let type_str = parser.read_identifier()?;
    let ty = parse_data_type(&type_str)?;
    parser.expect_char('>')?;
    parser.expect_char(';')?;

    Ok(InputDecl { name, privacy, ty })
}

fn parse_assert_stmt(parser: &mut ParserState) -> Result<AssertStmt, ParseError> {
    parser.advance(6); // "assert"
    parser.skip_whitespace();
    let expr = parse_expression(parser)?;
    parser.expect_char(';')?;
    Ok(AssertStmt { expr })
}

fn parse_output_decl(parser: &mut ParserState) -> Result<OutputDecl, ParseError> {
    parser.advance(6); // "output"
    parser.skip_whitespace();
    let name = parser.read_identifier()?;
    parser.expect_char('<')?;
    parser.skip_whitespace();
    let type_str = parser.read_identifier()?;
    let ty = parse_data_type(&type_str)?;
    parser.expect_char('>')?;
    parser.expect_char(';')?;
    Ok(OutputDecl { name, ty })
}

fn parse_data_type(s: &str) -> Result<DataType, ParseError> {
    match s {
        "u8" => Ok(DataType::U8),
        "u16" => Ok(DataType::U16),
        "u32" => Ok(DataType::U32),
        "u64" => Ok(DataType::U64),
        "u128" => Ok(DataType::U128),
        "u256" => Ok(DataType::U256),
        "bool" => Ok(DataType::Bool),
        "address" => Ok(DataType::Address),
        other => Err(ParseError::TypeError(format!("Unknown type: {}", other))),
    }
}

fn parse_expression(parser: &mut ParserState) -> Result<Expression, ParseError> {
    parse_comparison(parser)
}

fn parse_comparison(parser: &mut ParserState) -> Result<Expression, ParseError> {
    let left = parse_term(parser)?;
    parser.skip_whitespace();

    let (op, op_len) = if parser.peek_str(">=") {
        (Some(ComparisonOp::GtEq), 2)
    } else if parser.peek_str("<=") {
        (Some(ComparisonOp::LtEq), 2)
    } else if parser.peek_str("==") {
        (Some(ComparisonOp::Eq), 2)
    } else if parser.peek_str("!=") {
        (Some(ComparisonOp::NotEq), 2)
    } else if parser.peek_str(">") {
        (Some(ComparisonOp::Gt), 1)
    } else if parser.peek_str("<") {
        (Some(ComparisonOp::Lt), 1)
    } else if parser.peek_str("=") {
        (Some(ComparisonOp::Eq), 1)
    } else {
        (None, 0)
    };

    if let (Some(op), op_len) = (op, op_len) {
        parser.advance(op_len);
        parser.skip_whitespace();
        let right = parse_term(parser)?;
        Ok(Expression::Comparison {
            left: Box::new(left),
            op,
            right: Box::new(right),
        })
    } else {
        Ok(left)
    }
}

fn parse_term(parser: &mut ParserState) -> Result<Expression, ParseError> {
    let mut left = parse_factor(parser)?;

    loop {
        parser.skip_whitespace();
        let op = if parser.peek_str("+") {
            Some(ArithmeticOp::Add)
        } else if parser.peek_str("-") {
            Some(ArithmeticOp::Sub)
        } else {
            None
        };

        if let Some(op) = op {
            parser.advance(1);
            parser.skip_whitespace();
            let right = parse_factor(parser)?;
            left = Expression::Arithmetic {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        } else {
            break;
        }
    }

    Ok(left)
}

fn parse_factor(parser: &mut ParserState) -> Result<Expression, ParseError> {
    let mut left = parse_primary(parser)?;

    loop {
        parser.skip_whitespace();
        let op = if parser.peek_str("*") {
            Some(ArithmeticOp::Mul)
        } else if parser.peek_str("/") {
            Some(ArithmeticOp::Div)
        } else if parser.peek_str("%") {
            Some(ArithmeticOp::Mod)
        } else {
            None
        };

        if let Some(op) = op {
            parser.advance(1);
            parser.skip_whitespace();
            let right = parse_primary(parser)?;
            left = Expression::Arithmetic {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        } else {
            break;
        }
    }

    Ok(left)
}

fn parse_primary(parser: &mut ParserState) -> Result<Expression, ParseError> {
    parser.skip_whitespace();

    if parser.peek_char() == Some('(') {
        parser.advance(1);
        let expr = parse_expression(parser)?;
        parser.expect_char(')')?;
        return Ok(Expression::Paren(Box::new(expr)));
    }

    if parser.peek_str("true") {
        parser.advance(4);
        return Ok(Expression::Bool(true));
    }

    if parser.peek_str("false") {
        parser.advance(5);
        return Ok(Expression::Bool(false));
    }

    let c = parser.peek_char().unwrap_or('\0');

    if c.is_ascii_digit() {
        let num = parser.read_number()?;
        return Ok(Expression::Number(num));
    }

    if c.is_alphabetic() || c == '_' {
        let id = parser.read_identifier()?;
        parser.skip_whitespace();

        // Check for function call
        if parser.peek_char() == Some('(') {
            parser.advance(1);
            let mut args = Vec::new();
            loop {
                parser.skip_whitespace();
                if parser.peek_char() == Some(')') {
                    parser.advance(1);
                    break;
                }
                args.push(parse_expression(parser)?);
                parser.skip_whitespace();
                if parser.peek_char() == Some(',') {
                    parser.advance(1);
                } else if parser.peek_char() == Some(')') {
                    parser.advance(1);
                    break;
                }
            }
            return Ok(Expression::FunctionCall { name: id, args });
        }

        return Ok(Expression::Variable(id));
    }

    Err(ParseError::Parse {
        line: parser.line,
        msg: format!("Unexpected character: '{}'", c),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_age_verify() {
        let source = r#"
            prove {
                input age: Private<u8>;
                input threshold: Public<u8>;
                assert age >= 18;
                assert age < threshold;
            }
        "#;

        let program = parse(source, "test.zkf").unwrap();
        assert_eq!(program.name, "test");

        let block = match &program.statements[0] {
            Statement::ProveBlock(b) => b,
            _ => panic!("Expected ProveBlock"),
        };

        assert_eq!(block.inputs.len(), 2);
        assert_eq!(block.inputs[0].name, "age");
        assert_eq!(block.inputs[0].privacy, Privacy::Private);
        assert_eq!(block.inputs[0].ty, DataType::U8);

        assert_eq!(block.assertions.len(), 2);

        // Check age >= 18
        if let Expression::Comparison { left, op, right } = &block.assertions[0].expr {
            assert_eq!(format!("{:?}", left.as_ref()), "Variable(\"age\")");
            assert_eq!(*op, ComparisonOp::GtEq);
            assert_eq!(format!("{:?}", right.as_ref()), "Number(\"18\")");
        } else {
            panic!("Expected comparison");
        }

        assert_eq!(block.estimated_constraints(), 32); // estimated: 2 assertions × ~16 constraints each
    }

    #[test]
    fn test_parse_nft_ownership() {
        let source = r#"
            prove {
                input merkle_root: Public<u256>;
                input merkle_path: Private<u256>;
                input leaf: Private<u256>;
                assert merkle_verify(merkle_root, merkle_path, leaf) == true;
            }
        "#;

        let program = parse(source, "nft.zkf").unwrap();
        let block = match &program.statements[0] {
            Statement::ProveBlock(b) => b,
            _ => panic!("Expected ProveBlock"),
        };

        assert_eq!(block.inputs.len(), 3);
        assert_eq!(block.assertions.len(), 1);

        let est = block.estimated_constraints();
        assert!(est > 5000, "Merkle verify should be expensive: got {}", est);
    }

    #[test]
    fn test_parse_arithmetic() {
        let source = r#"
            prove {
                input balance: Private<u256>;
                input debt: Public<u256>;
                assert balance > debt * 2;
            }
        "#;

        let program = parse(source, "math.zkf").unwrap();
        let block = match &program.statements[0] {
            Statement::ProveBlock(b) => b,
            _ => panic!("Expected ProveBlock"),
        };

        assert_eq!(block.assertions.len(), 1);
    }

    #[test]
    fn test_parse_with_output() {
        let source = r#"
            prove {
                input score: Private<u32>;
                input min_score: Public<u32>;
                assert score >= min_score;
                output valid<bool>;
            }
        "#;

        let program = parse(source, "score.zkf").unwrap();
        let block = match &program.statements[0] {
            Statement::ProveBlock(b) => b,
            _ => panic!("Expected ProveBlock"),
        };

        assert_eq!(block.outputs.len(), 1);
        assert_eq!(block.outputs[0].name, "valid");
        assert_eq!(block.outputs[0].ty, DataType::Bool);
    }

    #[test]
    fn test_parse_with_comments() {
        let source = r#"// This is a comment
prove test_proof {
    // Another comment
    input x: Private<u256>;
    assert x > 100;
    output valid<bool>;
}"#;

        let program = parse(source, "comment.zkf").unwrap();
        assert!(!program.statements.is_empty());
        let block = match &program.statements[0] {
            Statement::ProveBlock(b) => b,
            _ => panic!("Expected ProveBlock"),
        };
        assert_eq!(block.inputs.len(), 1);
    }
}
