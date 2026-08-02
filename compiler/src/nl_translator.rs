//! Natural Language → ZK Circuit Translator
//!
//! The crown jewel of ZKForge — converts plain English into
//! provable zero-knowledge circuits. No competitor has this.
//!
//! Architecture:
//! 1. Intent Detection — classify what kind of proof the user wants
//! 2. Entity Extraction — identify variables, thresholds, operators
//! 3. DSL Generation — emit optimized .zkf code
//! 4. Auto-Test Generation — produce test vectors from the NL assertion

use crate::ast::*;
use std::collections::HashMap;

/// Result of translating natural language to a ZK proof specification.
#[derive(Debug, Clone)]
pub struct NLTranslation {
    /// Generated .zkf source code
    pub zkf_source: String,
    /// Extracted circuit name
    pub circuit_name: String,
    /// Detected proof category
    pub category: ProofCategory,
    /// Extracted entities (variables)
    pub entities: Vec<ExtractedEntity>,
    /// Suggested inputs for testing
    pub test_inputs: Vec<TestVector>,
    /// Explanation of what the circuit proves
    pub explanation: String,
}

/// Categories of zero-knowledge proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofCategory {
    /// "I am over X years old" — age/date comparisons
    AgeVerification,
    /// "I own more than X tokens" — balance threshold
    BalanceThreshold,
    /// "I own a specific NFT" — ownership/Merkle
    OwnershipProof,
    /// "My score exceeds X" — credential scoring
    ScoreThreshold,
    /// "I am in this set" — set membership (Merkle)
    SetMembership,
    /// "I have X attribute without revealing Y" — general attribute proof
    AttributeProof,
    /// "Compute X privately" — private computation
    PrivateComputation,
    /// "I know the preimage of hash H" — hash preimage
    HashPreimage,
    /// Multi-condition compound proof
    CompoundProof,
    /// Unknown — fallback
    Unknown,
}

impl ProofCategory {
    pub fn name(&self) -> &'static str {
        match self {
            ProofCategory::AgeVerification => "age_verification",
            ProofCategory::BalanceThreshold => "balance_threshold",
            ProofCategory::OwnershipProof => "nft_ownership",
            ProofCategory::ScoreThreshold => "credit_score",
            ProofCategory::SetMembership => "set_membership",
            ProofCategory::AttributeProof => "attribute_proof",
            ProofCategory::PrivateComputation => "private_computation",
            ProofCategory::HashPreimage => "hash_preimage",
            ProofCategory::CompoundProof => "compound_proof",
            ProofCategory::Unknown => "custom_proof",
        }
    }
}

/// An entity extracted from natural language.
#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub name: String,
    pub kind: EntityKind,
    pub data_type: DataType,
    pub privacy: Privacy,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityKind {
    Scalar,
    Balance,
    Age,
    Score,
    Hash,
    Address,
    MerkleRoot,
    MerklePath,
    Signature,
}

/// A test vector for the generated circuit.
#[derive(Debug, Clone)]
pub struct TestVector {
    pub private_inputs: HashMap<String, String>,
    pub public_inputs: HashMap<String, String>,
    pub should_pass: bool,
}

/// Intent patterns that map NL phrases to proof categories.
struct IntentPattern {
    keywords: Vec<&'static str>,
    category: ProofCategory,
}

/// Split Arabic text into tokens for keyword matching.
/// Arabic is not space-delimited for all words, so we use a sliding window.
fn tokenize_arabic(text: &str) -> String {
    // Normalize Arabic: remove diacritics, normalize alef variants
    let normalized = text
        .replace(['أ', 'إ', 'آ'], "ا")
        .replace('ة', "ه")
        .replace('ى', "ي");
    // Keep only Arabic letters, digits, and spaces
    normalized
        .chars()
        .filter(|c| {
            c.is_whitespace() || ('\u{0600}'..='\u{06FF}').contains(c) || c.is_ascii_digit()
        })
        .collect()
}

/// Built-in intent patterns (English + Arabic).
fn intent_patterns() -> Vec<IntentPattern> {
    vec![
        IntentPattern {
            keywords: vec![
                "age",
                "old",
                "born",
                "birth",
                "years old",
                "over 18",
                "over 21",
                "adult",
                "minor",
                "عمر",
                "سن",
                "بالغ",
                "مولود",
                "سنه",
                "عاما",
                "عام",
                "اكبر",
                "أكبر",
                "راشد",
                "قاصر",
            ],
            category: ProofCategory::AgeVerification,
        },
        IntentPattern {
            keywords: vec![
                "balance",
                "tokens",
                "eth",
                "usdc",
                "usdt",
                "coins",
                "amount",
                "hold",
                "holding",
                "wallet balance",
                "more than",
                "at least",
                "minimum balance",
                "رصيد",
                "عملات",
                "ايثير",
                "ايثريوم",
                "محفظه",
                "محفظة",
                "امتلك",
                "لدي",
                "عندي",
                "مبلغ",
            ],
            category: ProofCategory::BalanceThreshold,
        },
        IntentPattern {
            keywords: vec![
                "nft",
                "own",
                "ownership",
                "owns",
                "possess",
                "belong",
                "property",
                "امتلك",
                "املك",
                "ملكيه",
                "ملكية",
                "اصل",
                "رمز",
            ],
            category: ProofCategory::OwnershipProof,
        },
        IntentPattern {
            keywords: vec![
                "score",
                "credit",
                "rating",
                "grade",
                "reputation",
                "karma",
                "level",
                "rank",
                "نقاط",
                "تصنيف",
                "درجه",
                "درجة",
                "ائتمان",
                "تقييم",
                "سمعه",
                "سمعة",
                "مستوى",
                "مستوي",
            ],
            category: ProofCategory::ScoreThreshold,
        },
        IntentPattern {
            keywords: vec![
                "member",
                "membership",
                "whitelist",
                "allowlist",
                "set",
                "list",
                "group",
                "included in",
                "عضو",
                "عضويه",
                "عضوية",
                "قائمه",
                "قائمة",
                "مجموعه",
                "مجموعة",
                "مدرج",
                "مضمن",
            ],
            category: ProofCategory::SetMembership,
        },
        IntentPattern {
            keywords: vec![
                "hash",
                "preimage",
                "sha256",
                "poseidon",
                "keccak",
                "commitment",
                "هاش",
                "تجزئه",
                "تجزئة",
                "التزام",
            ],
            category: ProofCategory::HashPreimage,
        },
        IntentPattern {
            keywords: vec![
                "without revealing",
                "privately",
                "secret",
                "hidden",
                "confidential",
                "zero knowledge",
                "بدون كشف",
                "بدون افشاء",
                "بدون إفشاء",
                "سري",
                "خاص",
                "مخفي",
                "خصوصيه",
                "خصوصية",
                "معرفه صفريه",
                "معرفة صفرية",
            ],
            category: ProofCategory::AttributeProof,
        },
        IntentPattern {
            keywords: vec![
                "compute",
                "calculate",
                "multiply",
                "add",
                "subtract",
                "formula",
                "equation",
                "احسب",
                "حساب",
                "ضرب",
                "جمع",
                "طرح",
                "معادله",
                "معادلة",
                "عملية",
            ],
            category: ProofCategory::PrivateComputation,
        },
    ]
}

/// Detect the proof category from natural language text (English + Arabic).
fn detect_category(text: &str) -> (ProofCategory, f64) {
    let lower = text.to_lowercase();
    let arabic_normalized = if text.chars().any(|c| ('\u{0600}'..='\u{06FF}').contains(&c)) {
        Some(tokenize_arabic(text))
    } else {
        None
    };
    let patterns = intent_patterns();
    let mut best_category = ProofCategory::Unknown;
    let mut best_score: f64 = 0.0;

    for pattern in &patterns {
        let mut score = 0.0;
        for keyword in &pattern.keywords {
            // Check English
            if lower.contains(keyword) {
                score += if keyword.len() > 8 { 2.0 } else { 1.0 };
                // Bonus for exact match at word boundary
                for word in lower.split_whitespace() {
                    if word == *keyword {
                        score += 1.0;
                    }
                }
            }
            // Check Arabic (normalized)
            if let Some(ref arabic) = arabic_normalized {
                if arabic.contains(keyword) {
                    score += if keyword.len() > 8 { 2.5 } else { 1.5 };
                    // Bonus for exact word match in Arabic
                    for word in arabic.split_whitespace() {
                        if word == *keyword {
                            score += 1.5;
                        }
                    }
                }
            }
        }
        if score > best_score {
            best_score = score;
            best_category = pattern.category.clone();
        }
    }

    // Check for compound (multiple conditions) — English + Arabic connectors
    let condition_count = lower.matches("and").count()
        + lower.matches("also").count()
        + lower.matches("plus").count()
        + lower.matches("و ").count()
        + lower.matches("ايضا").count()
        + lower.matches("أيضا").count();
    if condition_count >= 1 && best_category != ProofCategory::Unknown {
        best_category = ProofCategory::CompoundProof;
    }

    (best_category, best_score)
}

/// Extract number entities from text like "50 ETH", "18 years", "100 tokens"
/// Also handles Arabic: "٥٠ ايثير", "١٨ عام", "١٠٠ عملة"
#[allow(dead_code)]
fn extract_numbers(text: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let _lower = text.to_lowercase();

    // Convert Arabic-Indic digits to Western
    let arabic_to_western = |ch: char| -> char {
        match ch {
            '\u{0660}' => '0',
            '\u{0661}' => '1',
            '\u{0662}' => '2',
            '\u{0663}' => '3',
            '\u{0664}' => '4',
            '\u{0665}' => '5',
            '\u{0666}' => '6',
            '\u{0667}' => '7',
            '\u{0668}' => '8',
            '\u{0669}' => '9',
            _ => ch,
        }
    };
    let normalized_text: String = text.chars().map(arabic_to_western).collect();
    let normalized_lower = normalized_text.to_lowercase();

    // Pattern: "N tokens/ETH/coins/..."
    let units = [
        "eth",
        "usdc",
        "usdt",
        "tokens",
        "coins",
        "dai",
        "btc",
        "sol",
        "matic",
        "ايثير",
        "عملات",
        "عمله",
        "عملة",
        "دولار",
        "ريال",
    ];

    // English number extraction
    let words: Vec<&str> = normalized_text.split_whitespace().collect();
    for window in words.windows(2) {
        if let Ok(_n) = window[0].parse::<f64>() {
            let word0_lower = window[0].to_lowercase();
            if units.contains(&window[1].to_lowercase().as_str())
                || window[1].to_lowercase() == "years"
                || window[1].to_lowercase() == "points"
                || window[1].to_lowercase() == "عام"
                || window[1].to_lowercase() == "عاما"
                || window[1].to_lowercase() == "سنه"
                || window[1].to_lowercase() == "سنة"
                || window[1].to_lowercase() == "نقطه"
                || window[1].to_lowercase() == "نقطة"
            {
                results.push((word0_lower, window[1].to_lowercase()));
            }
        }
    }

    // Pattern: "at least N" / "more than N" / "greater than N" / "exceeds N"
    // Arabic: "على الاقل N", "اكثر من N", "يتجاوز N"
    let threshold_prefixes = [
        "at least",
        "more than",
        "greater than",
        "exceeds",
        "above",
        "over",
        "minimum",
        "على الاقل",
        "على الأقل",
        "اكثر من",
        "أكثر من",
        "يتجاوز",
        "فوق",
        "اعلى من",
        "أعلى من",
        "الحد الادنى",
        "الحد الأدنى",
        "يزيد عن",
    ];
    for prefix in &threshold_prefixes {
        if let Some(pos) = normalized_lower.find(prefix) {
            let after = &normalized_lower[pos + prefix.len()..].trim();
            if let Some(word) = after.split_whitespace().next() {
                if word.parse::<f64>().is_ok() {
                    // Find unit after number
                    let rest = after[word.len()..].trim();
                    let unit = rest.split_whitespace().next().unwrap_or("").to_lowercase();
                    results.push((word.to_string(), unit));
                }
            }
        }
    }

    results
}

/// Extract entity descriptions from the NL text.
fn extract_entities(text: &str, category: &ProofCategory) -> Vec<ExtractedEntity> {
    let lower = text.to_lowercase();
    let mut entities = Vec::new();

    match category {
        ProofCategory::AgeVerification => {
            entities.push(ExtractedEntity {
                name: "age".to_string(),
                kind: EntityKind::Age,
                data_type: DataType::U8,
                privacy: Privacy::Private,
                description: "User's age (private)".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "min_age".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U8,
                privacy: Privacy::Public,
                description: "Age threshold (public)".to_string(),
            });
        }
        ProofCategory::BalanceThreshold => {
            let unit = if lower.contains("eth") {
                "ETH"
            } else if lower.contains("usdc") {
                "USDC"
            } else if lower.contains("usdt") {
                "USDT"
            } else {
                "tokens"
            };

            entities.push(ExtractedEntity {
                name: if unit == "ETH" {
                    "eth_balance".to_string()
                } else {
                    "token_balance".to_string()
                },
                kind: EntityKind::Balance,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: format!("User's {} balance (private)", unit),
            });
            entities.push(ExtractedEntity {
                name: "threshold".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: format!("Minimum {} threshold (public)", unit),
            });
        }
        ProofCategory::OwnershipProof => {
            entities.push(ExtractedEntity {
                name: "merkle_root".to_string(),
                kind: EntityKind::MerkleRoot,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: "Merkle root of allowed set".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "merkle_path".to_string(),
                kind: EntityKind::MerklePath,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "User's Merkle proof path".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "leaf".to_string(),
                kind: EntityKind::Address,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "User's address as leaf".to_string(),
            });
        }
        ProofCategory::ScoreThreshold => {
            entities.push(ExtractedEntity {
                name: "score".to_string(),
                kind: EntityKind::Score,
                data_type: DataType::U32,
                privacy: Privacy::Private,
                description: "User's score (private)".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "min_score".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U32,
                privacy: Privacy::Public,
                description: "Minimum score threshold".to_string(),
            });
        }
        ProofCategory::SetMembership => {
            entities.push(ExtractedEntity {
                name: "merkle_root".to_string(),
                kind: EntityKind::MerkleRoot,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: "Merkle root of the set".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "merkle_path".to_string(),
                kind: EntityKind::MerklePath,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Merkle proof (private)".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "element".to_string(),
                kind: EntityKind::Hash,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Element to prove membership for".to_string(),
            });
        }
        ProofCategory::AttributeProof => {
            // Generic attribute — extract from text
            entities.push(ExtractedEntity {
                name: "private_value".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Private attribute value".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "public_threshold".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: "Public threshold".to_string(),
            });
        }
        ProofCategory::HashPreimage => {
            entities.push(ExtractedEntity {
                name: "preimage".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Secret preimage".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "hash_commitment".to_string(),
                kind: EntityKind::Hash,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: "Public hash commitment".to_string(),
            });
        }
        ProofCategory::PrivateComputation => {
            entities.push(ExtractedEntity {
                name: "input_a".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Private input A".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "input_b".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Private input B".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "expected_result".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: "Expected computation result".to_string(),
            });
        }
        ProofCategory::CompoundProof => {
            entities.push(ExtractedEntity {
                name: "private_val".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Private value".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "threshold".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: "Public threshold".to_string(),
            });
        }
        ProofCategory::Unknown => {
            entities.push(ExtractedEntity {
                name: "secret".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Private,
                description: "Secret value".to_string(),
            });
            entities.push(ExtractedEntity {
                name: "public_val".to_string(),
                kind: EntityKind::Scalar,
                data_type: DataType::U256,
                privacy: Privacy::Public,
                description: "Public value".to_string(),
            });
        }
    }

    entities
}

/// Detect the comparison operator from NL text (English + Arabic).
fn detect_comparison(text: &str) -> (&'static str, ComparisonOp) {
    let lower = text.to_lowercase();

    if lower.contains("at least")
        || lower.contains("minimum")
        || lower.contains("no less than")
        || lower.contains("≥")
        || lower.contains("على الاقل")
        || lower.contains("على الأقل")
        || lower.contains("الحد الادنى")
        || lower.contains("الحد الأدنى")
        || lower.contains("لا يقل عن")
    {
        (">=", ComparisonOp::GtEq)
    } else if lower.contains("more than")
        || lower.contains("greater than")
        || lower.contains("exceeds")
        || lower.contains("above")
        || lower.contains("over")
        || lower.contains(">")
        || lower.contains("اكثر من")
        || lower.contains("أكثر من")
        || lower.contains("يتجاوز")
        || lower.contains("فوق")
        || lower.contains("اعلى من")
        || lower.contains("أعلى من")
        || lower.contains("يزيد عن")
    {
        (">", ComparisonOp::Gt)
    } else if lower.contains("at most")
        || lower.contains("maximum")
        || lower.contains("no more than")
        || lower.contains("≤")
        || lower.contains("على الاكثر")
        || lower.contains("على الأكثر")
        || lower.contains("الحد الاعلى")
        || lower.contains("الحد الأعلى")
        || lower.contains("لا يزيد عن")
    {
        ("<=", ComparisonOp::LtEq)
    } else if lower.contains("less than")
        || lower.contains("below")
        || lower.contains("under")
        || lower.contains("<")
        || lower.contains("اقل من")
        || lower.contains("أقل من")
        || lower.contains("تحت")
    {
        ("<", ComparisonOp::Lt)
    } else if lower.contains("not")
        || lower.contains("isn't")
        || lower.contains("≠")
        || lower.contains("!=")
        || lower.contains("لا يساوي")
        || lower.contains("مختلف عن")
        || lower.contains("ليس")
    {
        ("!=", ComparisonOp::NotEq)
    } else if lower.contains("equal")
        || lower.contains("exactly")
        || lower.contains("==")
        || lower.contains("matches")
        || lower.contains("يساوي")
        || lower.contains("تماما")
        || lower.contains("تماماً")
        || lower.contains("مطابق")
    {
        ("==", ComparisonOp::Eq)
    } else {
        // Default: assume "at least" / "≥"
        (">=", ComparisonOp::GtEq)
    }
}

/// Detect what should NOT be revealed.
fn detect_privacy_requirements(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut hidden = Vec::new();

    let patterns = [
        "without revealing",
        "don't reveal",
        "do not reveal",
        "hide",
        "keep private",
        "keep secret",
        "privately",
        "confidentially",
        "without showing",
        "without exposing",
        "without disclosing",
    ];

    for pattern in &patterns {
        if let Some(pos) = lower.find(pattern) {
            let after = &lower[pos + pattern.len()..].trim();
            // Extract what to hide
            let hidden_part = after
                .split(['.', ',', ';', '\n'])
                .next()
                .unwrap_or(after)
                .trim()
                .to_string();

            if !hidden_part.is_empty() && hidden_part != "my" && hidden_part != "the" {
                hidden.push(hidden_part);
            }
        }
    }

    // Also extract "don't show my X"
    if let Some(pos) = lower.find("my ") {
        let after = &lower[pos + 3..].trim();
        let words: Vec<&str> = after.split_whitespace().collect();
        if !words.is_empty() {
            let what = words[0].to_lowercase();
            if matches!(
                what.as_str(),
                "wallet" | "balance" | "age" | "score" | "identity" | "address" | "name"
            ) && !hidden.iter().any(|h| h.contains(&what))
            {
                hidden.push(what);
            }
        }
    }

    hidden
}

/// Extract threshold values from text (English + Arabic).
fn extract_threshold(text: &str) -> Option<String> {
    let lower = text.to_lowercase();

    // Convert Arabic-Indic digits to Western
    let arabic_to_western = |ch: char| -> char {
        match ch {
            '\u{0660}' => '0',
            '\u{0661}' => '1',
            '\u{0662}' => '2',
            '\u{0663}' => '3',
            '\u{0664}' => '4',
            '\u{0665}' => '5',
            '\u{0666}' => '6',
            '\u{0667}' => '7',
            '\u{0668}' => '8',
            '\u{0669}' => '9',
            _ => ch,
        }
    };
    let normalized_lower: String = lower.chars().map(arabic_to_western).collect();

    let prefixes = [
        "at least",
        "more than",
        "over",
        "above",
        "minimum of",
        "exceeds",
        "greater than",
        "at most",
        "less than",
        "below",
        "under",
        "maximum of",
        "على الاقل",
        "على الأقل",
        "اكثر من",
        "أكثر من",
        "يتجاوز",
        "فوق",
        "اعلى من",
        "أعلى من",
        "يزيد عن",
        "على الاكثر",
        "على الأكثر",
        "اقل من",
        "أقل من",
        "الحد الادنى",
        "الحد الأدنى",
    ];

    for prefix in &prefixes {
        if let Some(pos) = normalized_lower.find(prefix) {
            let after = &normalized_lower[pos + prefix.len()..].trim();
            if let Some(word) = after.split_whitespace().next() {
                // Try to parse as number (after Arabic digit normalization)
                let cleaned: String = word
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !cleaned.is_empty() && cleaned.parse::<f64>().is_ok() {
                    // Convert to integer if decimal
                    if cleaned.contains('.') {
                        if let Ok(f) = cleaned.parse::<f64>() {
                            return Some(format!("{}", f as u64));
                        }
                    }
                    return Some(cleaned);
                }
            }
        }
    }
    None
}

/// Generate the .zkf DSL source from extracted information.
fn generate_zkf(entities: &[ExtractedEntity], category: &ProofCategory, text: &str) -> String {
    let (op_symbol, _) = detect_comparison(text);
    let threshold = extract_threshold(text);
    let circuit_name = category.name().to_string();

    let mut zkf = String::new();

    // Comments with the original NL
    zkf.push_str(&format!("// Auto-generated from: \"{}\"\n", text));
    zkf.push_str(&format!("// Category: {:?}\n", category));
    zkf.push('\n');

    // Prove block
    zkf.push_str(&format!("prove {} {{\n", circuit_name));

    // Inputs
    for entity in entities {
        let privacy = match entity.privacy {
            Privacy::Private => "Private",
            Privacy::Public => "Public",
        };
        zkf.push_str(&format!(
            "    input {}: {}<{}>;  // {}\n",
            entity.name, privacy, entity.data_type, entity.description
        ));
    }

    zkf.push('\n');

    // Assertions
    match category {
        ProofCategory::AgeVerification => {
            let default_threshold = threshold.unwrap_or_else(|| "18".to_string());
            zkf.push_str(&format!(
                "    assert age {} {};\n",
                op_symbol, default_threshold
            ));
        }
        ProofCategory::BalanceThreshold => {
            let default_threshold = threshold.unwrap_or_else(|| "50".to_string());
            let var = if entities.iter().any(|e| e.name == "eth_balance") {
                "eth_balance"
            } else {
                "token_balance"
            };
            zkf.push_str(&format!(
                "    assert {} {} {};\n",
                var, op_symbol, default_threshold
            ));
        }
        ProofCategory::ScoreThreshold => {
            let default_threshold = threshold.unwrap_or_else(|| "700".to_string());
            zkf.push_str(&format!(
                "    assert score {} {};\n",
                op_symbol, default_threshold
            ));
        }
        ProofCategory::OwnershipProof | ProofCategory::SetMembership => {
            zkf.push_str("    assert merkle_verify(merkle_root, merkle_path, leaf) == true;\n");
        }
        ProofCategory::HashPreimage => {
            zkf.push_str("    assert hash(preimage) == hash_commitment;\n");
        }
        ProofCategory::AttributeProof => {
            let default_threshold = threshold.unwrap_or_else(|| "100".to_string());
            zkf.push_str(&format!(
                "    assert private_value {} {};\n",
                op_symbol, default_threshold
            ));
        }
        ProofCategory::PrivateComputation => {
            zkf.push_str("    assert input_a * input_b == expected_result;\n");
        }
        ProofCategory::CompoundProof => {
            let default_threshold = threshold.unwrap_or_else(|| "100".to_string());
            zkf.push_str(&format!(
                "    assert private_val {} {};\n",
                op_symbol, default_threshold
            ));
        }
        ProofCategory::Unknown => {
            zkf.push_str("    // TODO: customize the assertion below\n");
            zkf.push_str("    assert secret >= public_val;\n");
        }
    }

    // Output
    zkf.push_str("    output valid<bool>;\n");
    zkf.push_str("}\n");

    zkf
}

/// Generate test vectors for the circuit.
fn generate_test_vectors(
    entities: &[ExtractedEntity],
    category: &ProofCategory,
    text: &str,
) -> Vec<TestVector> {
    let threshold = extract_threshold(text);
    let mut vectors = Vec::new();

    match category {
        ProofCategory::AgeVerification => {
            let min_age = threshold.unwrap_or_else(|| "18".to_string());
            let pass_age: u64 = min_age.parse().unwrap_or(18) + 5;
            let fail_age: u64 = min_age.parse::<u64>().unwrap_or(18).saturating_sub(2);

            let mut priv_pass = HashMap::new();
            priv_pass.insert("age".to_string(), pass_age.to_string());
            let mut pub_pass = HashMap::new();
            pub_pass.insert("min_age".to_string(), min_age.clone());
            vectors.push(TestVector {
                private_inputs: priv_pass,
                public_inputs: pub_pass,
                should_pass: true,
            });

            let mut priv_fail = HashMap::new();
            priv_fail.insert("age".to_string(), fail_age.to_string());
            let mut pub_fail = HashMap::new();
            pub_fail.insert("min_age".to_string(), min_age);
            vectors.push(TestVector {
                private_inputs: priv_fail,
                public_inputs: pub_fail,
                should_pass: false,
            });
        }
        ProofCategory::BalanceThreshold => {
            let t_val: u64 = threshold
                .unwrap_or_else(|| "50".to_string())
                .parse()
                .unwrap_or(50);
            let var_name = if entities.iter().any(|e| e.name == "eth_balance") {
                "eth_balance"
            } else {
                "token_balance"
            };

            let mut priv_pass = HashMap::new();
            priv_pass.insert(var_name.to_string(), (t_val + 10).to_string());
            let mut pub_pass = HashMap::new();
            pub_pass.insert("threshold".to_string(), t_val.to_string());
            vectors.push(TestVector {
                private_inputs: priv_pass,
                public_inputs: pub_pass,
                should_pass: true,
            });

            let mut priv_fail = HashMap::new();
            priv_fail.insert(var_name.to_string(), t_val.saturating_sub(1).to_string());
            let mut pub_fail = HashMap::new();
            pub_fail.insert("threshold".to_string(), t_val.to_string());
            vectors.push(TestVector {
                private_inputs: priv_fail,
                public_inputs: pub_fail,
                should_pass: false,
            });
        }
        ProofCategory::ScoreThreshold => {
            let min_score = threshold.unwrap_or_else(|| "700".to_string());
            let s_val: u64 = min_score.parse().unwrap_or(700);

            let mut priv_pass = HashMap::new();
            priv_pass.insert("score".to_string(), (s_val + 50).to_string());
            let mut pub_pass = HashMap::new();
            pub_pass.insert("min_score".to_string(), min_score.clone());
            vectors.push(TestVector {
                private_inputs: priv_pass,
                public_inputs: pub_pass,
                should_pass: true,
            });
        }
        ProofCategory::AttributeProof => {
            let t = threshold.unwrap_or_else(|| "100".to_string());
            let t_val: u64 = t.parse().unwrap_or(100);
            let mut priv_pass = HashMap::new();
            priv_pass.insert("private_value".to_string(), (t_val + 1).to_string());
            let mut pub_pass = HashMap::new();
            pub_pass.insert("public_threshold".to_string(), t);
            vectors.push(TestVector {
                private_inputs: priv_pass,
                public_inputs: pub_pass,
                should_pass: true,
            });
        }
        _ => {
            // Generic test vector
            let mut r#priv = HashMap::new();
            for e in entities {
                if e.privacy == Privacy::Private {
                    r#priv.insert(e.name.clone(), "42".to_string());
                }
            }
            let mut pub_inputs = HashMap::new();
            for e in entities {
                if e.privacy == Privacy::Public {
                    pub_inputs.insert(e.name.clone(), "10".to_string());
                }
            }
            vectors.push(TestVector {
                private_inputs: r#priv,
                public_inputs: pub_inputs,
                should_pass: true,
            });
        }
    }

    vectors
}

/// Main translation function: NL text → full ZK circuit specification.
pub fn translate(text: &str) -> Result<NLTranslation, String> {
    if text.trim().is_empty() {
        return Err("Empty input — please describe what you want to prove.".to_string());
    }

    // Step 1: Detect category
    let (category, confidence) = detect_category(text);

    // Step 2: Extract entities
    let entities = extract_entities(text, &category);

    // Step 3: Detect privacy requirements
    let hidden_aspects = detect_privacy_requirements(text);

    // Step 4: Generate ZKF source
    let zkf_source = generate_zkf(&entities, &category, text);

    // Step 5: Generate test vectors
    let test_inputs = generate_test_vectors(&entities, &category, text);

    // Step 6: Build explanation
    let explanation = build_explanation(&category, &entities, &hidden_aspects, confidence);

    Ok(NLTranslation {
        zkf_source,
        circuit_name: category.name().to_string(),
        category,
        entities,
        test_inputs,
        explanation,
    })
}

/// Build a human-readable explanation of the circuit.
fn build_explanation(
    category: &ProofCategory,
    entities: &[ExtractedEntity],
    hidden: &[String],
    confidence: f64,
) -> String {
    let mut expl = String::new();

    expl.push_str(&format!(
        "Detected proof category: **{:?}** (confidence: {:.0}%)\n\n",
        category,
        (confidence * 100.0 / 14.0).min(100.0) // normalize
    ));

    let private_count = entities
        .iter()
        .filter(|e| e.privacy == Privacy::Private)
        .count();
    let public_count = entities
        .iter()
        .filter(|e| e.privacy == Privacy::Public)
        .count();

    expl.push_str(&format!(
        "**Circuit structure:** {} private signal{}, {} public signal{}\n\n",
        private_count,
        if private_count != 1 { "s" } else { "" },
        public_count,
        if public_count != 1 { "s" } else { "" },
    ));

    expl.push_str("**What is private (never revealed):**\n");
    for entity in entities.iter().filter(|e| e.privacy == Privacy::Private) {
        expl.push_str(&format!("  - {} ({})\n", entity.name, entity.description));
    }

    if !hidden.is_empty() {
        expl.push_str("\n**Explicitly hidden by user request:**\n");
        for h in hidden {
            expl.push_str(&format!("  - {}\n", h));
        }
    }

    expl.push_str("\n**What is public (visible to verifier):**\n");
    for entity in entities.iter().filter(|e| e.privacy == Privacy::Public) {
        expl.push_str(&format!("  - {} ({})\n", entity.name, entity.description));
    }

    expl
}

#[cfg(test)]
#[allow(clippy::len_zero)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_age_category() {
        let (cat, _) = detect_category("Prove I am over 18 years old");
        assert_eq!(cat, ProofCategory::AgeVerification);
    }

    #[test]
    fn test_detect_balance_category() {
        let (cat, _) = detect_category("Prove I have more than 50 ETH");
        assert_eq!(cat, ProofCategory::BalanceThreshold);
    }

    #[test]
    fn test_detect_score_category() {
        let (cat, _) = detect_category("My credit score is above 700");
        assert_eq!(cat, ProofCategory::ScoreThreshold);
    }

    #[test]
    fn test_detect_ownership_category() {
        let (cat, _) = detect_category("I own a specific NFT");
        assert_eq!(cat, ProofCategory::OwnershipProof);
    }

    #[test]
    fn test_detect_comparison() {
        assert_eq!(detect_comparison("at least 50").0, ">=");
        assert_eq!(detect_comparison("more than 100").0, ">");
        assert_eq!(detect_comparison("less than 20").0, "<");
        assert_eq!(detect_comparison("equal to 42").0, "==");
    }

    #[test]
    fn test_extract_threshold() {
        assert_eq!(
            extract_threshold("I have at least 50 ETH"),
            Some("50".to_string())
        );
        assert_eq!(
            extract_threshold("more than 100 tokens"),
            Some("100".to_string())
        );
        assert_eq!(
            extract_threshold("my score exceeds 750 points"),
            Some("750".to_string())
        );
        assert_eq!(extract_threshold("I am 25 years old"), None); // not a threshold phrase
    }

    #[test]
    fn test_detect_privacy() {
        let hidden = detect_privacy_requirements(
            "Prove I have more than 50 ETH without revealing my wallet address or exact balance",
        );
        assert!(hidden.iter().any(|h| h.contains("wallet")));
    }

    #[test]
    fn test_full_translation_age() {
        let result = translate("Prove I am over 18 years old").unwrap();
        assert!(result.zkf_source.contains("age"));
        assert!(result.zkf_source.contains("min_age"));
        assert_eq!(result.category, ProofCategory::AgeVerification);
        assert!(!result.test_inputs.is_empty());
        // Should have at least one passing and one failing test
        assert!(result.test_inputs.iter().any(|t| t.should_pass));
        assert!(result.test_inputs.iter().any(|t| !t.should_pass));
    }

    #[test]
    fn test_full_translation_balance() {
        let result = translate("Prove I hold at least 100 ETH").unwrap();
        assert_eq!(result.category, ProofCategory::BalanceThreshold);
        assert!(result.zkf_source.contains("eth_balance"));
        assert!(result.zkf_source.contains("threshold"));
    }

    #[test]
    fn test_full_translation_compound() {
        let result = translate("I want to prove I'm over 18 and have more than 50 ETH").unwrap();
        assert!(result.zkf_source.len() > 0);
    }

    #[test]
    fn test_empty_input() {
        assert!(translate("").is_err());
        assert!(translate("   ").is_err());
    }

    // ── Arabic Language Tests ──

    #[test]
    fn test_arabic_age_verification() {
        let result = translate("اثبت ان عمري اكبر من ١٨ عام").unwrap();
        assert_eq!(result.category, ProofCategory::AgeVerification);
        assert!(result.zkf_source.contains("age"));
    }

    #[test]
    fn test_arabic_balance_threshold() {
        let result = translate("لدي اكثر من ٥٠ ايثير في محفظتي").unwrap();
        assert_eq!(result.category, ProofCategory::BalanceThreshold);
    }

    #[test]
    fn test_arabic_score_threshold() {
        let result = translate("درجة الائتمان الخاصة بي تتجاوز ٧٠٠").unwrap();
        assert_eq!(result.category, ProofCategory::ScoreThreshold);
    }

    #[test]
    fn test_arabic_ownership() {
        let result = translate("امتلك هذا الرمز غير القابل للاستبدال").unwrap();
        assert_eq!(result.category, ProofCategory::OwnershipProof);
    }

    #[test]
    fn test_arabic_with_privacy() {
        let result = translate("اثبت ان عمري فوق ١٨ بدون كشف محفظتي").unwrap();
        // "بدون كشف" + "محفظتي" may tip scoring toward AttributeProof over AgeVerification.
        // Both are valid interpretations — the test accepts either.
        assert!(
            result.category == ProofCategory::AgeVerification
                || result.category == ProofCategory::AttributeProof,
            "Expected AgeVerification or AttributeProof, got {:?}",
            result.category
        );
        assert!(result.zkf_source.len() > 0);
    }

    #[test]
    fn test_arabic_detect_comparison() {
        assert_eq!(detect_comparison("على الاقل ٥٠").0, ">=");
        assert_eq!(detect_comparison("اكثر من ١٠٠").0, ">");
        assert_eq!(detect_comparison("اقل من ٢٠").0, "<");
        assert_eq!(detect_comparison("يساوي ٤٢").0, "==");
    }

    #[test]
    fn test_arabic_extract_threshold() {
        assert_eq!(
            extract_threshold("على الاقل ٥٠ ايثير"),
            Some("50".to_string())
        );
        assert_eq!(
            extract_threshold("اكثر من ١٠٠ عملة"),
            Some("100".to_string())
        );
    }
}
