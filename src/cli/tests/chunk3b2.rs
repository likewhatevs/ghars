//! chunk3b continued: `validate_pat_xor` early-return coverage.
#![allow(clippy::unwrap_used)]

use super::chunk3a2::proxy_with_one_ca_cert;
use super::*;

/// validator iterates in `IndexMap` insert order and must early-
/// return on the bad Pat without examining the trailing good
/// one. Pins the early-return contract: the loop fires on the
/// first Pat that fails the shape gate and never visits later
/// entries. Pinned alongside the [good-pat, bad-pat] case so a
/// regression that filters/skips Pat entries (e.g. a hypothetical
/// "`find_first(predicate)`" rewrite that misorders) is caught
/// from both sides.
#[test]
fn validate_pat_xor_rejects_first_bad_pat_before_trailing_good_pat() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "bad-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some(String::new()),
            token_file: None,
        },
    );
    cfg.auth.insert(
        "good-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT_GOOD".into()),
            token_file: None,
        },
    );
    cfg.runners[0].auth = Some("good-pat".into());
    // Inverse pin via must_not_contain: the error must NOT
    // mention the trailing good Pat's name — early-return: the
    // validator stopped on the first bad one and never iterated
    // to the second.
    assert_pat_xor_rejects(
        &cfg,
        "bad-pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &["\"good-pat\""],
    );
}

/// Both-bad-Pat: when BOTH Pat entries are misconfigured,
/// the validator early-returns on the FIRST bad Pat (insert
/// order) and never examines the second. Pinned so a regression
/// that "accumulates" failures across multiple Pat entries (or
/// that misattributes the error to the second bad one) is
/// caught. `IndexMap` preserves insert order: [bad1, bad2]. The
/// fixture uses `cfg_with_pat_auth` for bad1, then manually
/// inserts bad2 with the same fault shape (`token_env=Some`("")).
#[test]
fn validate_pat_xor_rejects_first_bad_pat_when_both_pats_faulted() {
    let mut cfg = cfg_with_pat_auth("bad1", Some(""), None);
    cfg.auth.insert(
        "bad2".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some(String::new()),
            token_file: None,
        },
    );
    // Inverse pin via must_not_contain: the error must NOT
    // mention "bad2" — the validator early-returned on bad1
    // and never iterated to the second bad entry.
    assert_pat_xor_rejects(
        &cfg,
        "bad1",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &["\"bad2\""],
    );
}

/// Non-Pat `AuthSpec` variants (`Interactive`, `TokenFile`,
/// `GithubApp`) have no XOR shape to validate. The validator
/// loop walks every entry but no-ops on non-Pat variants. Pinned
/// so a future regression that fires on non-Pat variants is
/// caught.
///
/// Named `_accepts_` for naming
/// consistency with sibling positive tests
/// (`_accepts_token_env_only`, `_accepts_token_file_only`) —
/// "accepts" describes the observable contract (Ok return);
/// "skips" was implementation-coupled (the loop body's no-op
/// branch).
#[test]
fn validate_pat_xor_accepts_non_pat_auth_variants() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // Replace the default [auth.pat] with a non-Pat variant (Interactive).
    cfg.auth.clear();
    cfg.auth
        .insert("interactive".into(), crate::config::AuthSpec::Interactive);
    cfg.auth.insert(
        "tokenfile".into(),
        crate::config::AuthSpec::TokenFile {
            path: camino::Utf8PathBuf::from("/etc/ghars/regtok"),
        },
    );
    cfg.runners[0].auth = Some("interactive".into());
    validate_pat_xor(&cfg).expect("non-Pat AuthSpec variants must pass validation");
}

// -------- token_env / token_file shape gate tests -----------------

/// RLO Trojan Source: `token_env` containing U+202E
/// (Right-to-Left Override) rejects via the hidden-char gate.
/// Load-bearing for the security claim that bidi-override
/// attacks (Boucher & Anderson 2021) cannot reach apply-time
/// `env::var` lookup. RLO renders subsequent characters
/// right-to-left in operator terminals, allowing visually
/// identical strings to be different bytewise.
#[test]
fn validate_pat_xor_rejects_token_env_with_right_to_left_override() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{202E}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+202E", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// RLO Trojan Source on `token_file`: symmetric with the
/// `token_env` RLO pin above. A `token_file` path containing U+202E
/// (Right-to-Left Override) rejects via the hidden-char gate.
/// RLO inside a path is a credible attack surface — bidi-rendered
/// paths can disguise their actual byte sequence to a reviewing
/// operator (e.g. `/etc/ghars/Pat.txt` rendered as
/// `/etc/ghars/txt.taP` after RLO). Defense-in-depth pin so a
/// regression that drops U+202E from the matches arm but leaves
/// the `token_env` pin intact is still caught.
#[test]
fn validate_pat_xor_rejects_token_file_with_right_to_left_override() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/\u{202E}pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+202E", "byte offset"],
        &["/etc/ghars/pat"],
        &[],
    );
}

/// `token_env` containing U+200E (LRM, Left-to-Right Mark)
/// rejects via the hidden-char gate. LRM is in the U+200B..U+200F
/// block. Pinned to catch a regression that
/// re-narrows the explicit set to just ZWSP/ZWNJ/ZWJ.
#[test]
fn validate_pat_xor_rejects_token_env_with_left_to_right_mark() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{200E}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+200E", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env` containing U+2066 (LRI, Left-to-Right
/// Isolate) rejects via the hidden-char gate. Bidi isolate from
/// the U+2066..U+2069 block.
#[test]
fn validate_pat_xor_rejects_token_env_with_bidi_isolate() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{2066}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+2066", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_file` containing U+FE0F (VS-16, emoji variant selector)
/// rejects via the hidden-char gate. Variation selectors are Mn
/// (Mark, nonspacing) — NOT in the Cc class. Routes to the
/// remove-only sub-arm (no precomposed equivalent exists for VS).
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{FE0F}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+FE0F",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+034F (COMBINING GRAPHEME JOINER)
/// routes to the remove-only sub-arm of the Mn branch. CGJ is Mn
/// but has no precomposed NFC form, so NFC advice would mislead.
#[test]
fn validate_pat_xor_rejects_token_file_with_combining_grapheme_joiner() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{034F}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+034F",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+FE00 (VARIATION SELECTOR-1, low
/// boundary of U+FE00..=U+FE0F) routes to the remove-only
/// sub-arm. Pins the lower edge of the BMP VS range against an
/// off-by-one regression in the matches arm.
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector_1() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{FE00}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+FE00",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+E0100 (VARIATION SELECTOR-17, low
/// boundary of the supplementary VS17..=VS256 range at
/// U+E0100..=U+E01EF). Same threat shape as BMP VS chars: Mn but
/// no NFC composition. Pins the SMP boundary so a regression
/// that lists only the BMP range surfaces here.
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector_17() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{E0100}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+E0100",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+E01EF (VARIATION SELECTOR-256, high
/// boundary of the supplementary VS17..=VS256 range at
/// U+E0100..=U+E01EF). Pins the SMP closed-range upper edge —
/// symmetric with VS-16 (U+FE0F) pinning the BMP upper edge. A
/// regression that flips `..=` to `..` or truncates to U+E01EE
/// surfaces here.
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector_256() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{E01EF}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+E01EF",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+0483 (COMBINING CYRILLIC TITLO)
/// routes to the diacritical sub-arm: "combining mark" + offer
/// both remove-or-NFC remediations. The diacritical sub-arm is
/// the conservative default for any Mn codepoint not explicitly
/// listed in the no-NFC-form match.
#[test]
fn validate_pat_xor_rejects_token_file_with_cyrillic_combining_mark() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{0483}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+0483",
            "byte offset",
            "remove the codepoint",
            "precomposed (NFC) form",
            "if the character was intentional",
        ],
        &["/etc/ghars/pat"],
        &["no precomposed equivalent exists", "hidden character"],
    );
}

/// `token_env` containing U+061C (Arabic Letter Mark)
/// rejects via the hidden-char gate. ALM is one of the
/// individually-listed Cf-class chars.
#[test]
fn validate_pat_xor_rejects_token_env_with_arabic_letter_mark() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{061C}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+061C", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_file = "/etc/ghars/with\nnewline"` (embedded
/// newline in a path) rejects via the hidden-char gate.
/// ALL Cc chars reject in `token_file` — there is no `\t`
/// `\n` `\r` carve-out, so a path with a literal newline
/// cannot survive the hidden-char scan and slip past the
/// trim-mismatch gate (which only catches whitespace at the
/// path's edges) into apply where `open(2)` would either
/// succeed on a bizarre path or fail with confusing
/// diagnostics. Defense-in-depth pin against operator typos
/// and attacker-injected paths.
#[test]
fn validate_pat_xor_rejects_token_file_with_embedded_newline() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/with\nnewline"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+000A", "byte offset"],
        &["/etc/ghars/pat"],
        &["leading or trailing whitespace"],
    );
}

/// `token_file` with embedded TAB (U+0009) rejects via the
/// control-char arm. Symmetric with the embedded-newline pin;
/// the all-Cc rejection covers \t \n \r uniformly. Pinned
/// so a regression that carves out any one of the three is
/// caught.
#[test]
fn validate_pat_xor_rejects_token_file_with_embedded_tab() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/with\tab"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+0009", "byte offset"],
        &["/etc/ghars/pat"],
        &["leading or trailing whitespace"],
    );
}

/// `token_env = "_"` (single underscore) — the shortest
/// legal POSIX env var name MUST pass. Boundary check on the
/// regex's first-char class `[A-Za-z_]` paired with the `*`
/// quantifier on the trailing chars (zero-or-more allows a
/// single-char name).
#[test]
fn validate_pat_xor_accepts_token_env_single_underscore() {
    let cfg = cfg_with_pat_auth("pat", Some("_"), None);
    validate_pat_xor(&cfg).expect("single-underscore POSIX token_env must pass shape gate");
}

/// Multi-Pat where the first bad Pat fails on charset and
/// the second bad Pat fails on hidden-char. The validator
/// early-returns on the FIRST bad Pat — the diagnostic must
/// surface the charset gate's text, never the hidden-char text.
/// Pinned so a regression that "accumulates" or reorders the
/// fault evaluation across multi-Pat surfaces is caught.
#[test]
fn validate_pat_xor_rejects_first_bad_pat_charset_before_hidden_char_pat() {
    let mut cfg = cfg_with_pat_auth("bad-charset", Some("FOO-BAR"), None);
    cfg.auth.insert(
        "bad-hidden".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("FOO\u{FEFF}BAR".into()),
            token_file: None,
        },
    );
    assert_pat_xor_rejects(
        &cfg,
        "bad-charset",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["\"bad-hidden\"", "hidden character"],
    );
}

/// Reverse-ordering pin: multi-Pat where the FIRST entry
/// (`IndexMap` insertion order — `cfg.auth` is
/// `IndexMap<String, AuthSpec>` so iteration follows insertion,
/// NOT alphabetical) fails on hidden-char and the second entry
/// fails on charset. The validator early-returns on the first
/// bad Pat — the diagnostic must surface the hidden-char gate's
/// text, never the charset text. Symmetric with the
/// charset-before-hidden pin above; together they pin
/// iteration-order independence: whichever fault comes first in
/// `IndexMap` insertion order is the one surfaced, regardless of
/// fault class.
#[test]
fn validate_pat_xor_rejects_first_bad_pat_hidden_char_before_charset_pat() {
    let mut cfg = cfg_with_pat_auth("aa-bad-hidden", Some("FOO\u{FEFF}BAR"), None);
    cfg.auth.insert(
        "zz-bad-charset".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("FOO-BAR".into()),
            token_file: None,
        },
    );
    assert_pat_xor_rejects(
        &cfg,
        "aa-bad-hidden",
        &["token_env", "hidden character", "U+FEFF"],
        &["GHARS_PAT"],
        &["\"zz-bad-charset\"", "POSIX environment variable name"],
    );
}

/// `token_env` with a Cyrillic letter (U+0411 CYRILLIC
/// CAPITAL LETTER BE) rejects via the POSIX charset gate. The
/// regex's `[A-Za-z]` class is ASCII-only; non-ASCII letters
/// fail. Pinned so a regression that loosens the regex to
/// `\w` (Unicode word character) is caught.
#[test]
fn validate_pat_xor_rejects_token_env_with_cyrillic_letter() {
    let cfg = cfg_with_pat_auth("pat", Some("\u{0411}FOO"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["hidden character"],
    );
}

/// `token_env` with a fullwidth digit (U+FF11 FULLWIDTH
/// DIGIT ONE) rejects via the POSIX charset gate. Fullwidth
/// digits are Unicode `Nd` general category but outside the
/// ASCII `[0-9]` class. Pinned alongside Cyrillic so a future
/// regression that switches to `\d` is caught.
#[test]
fn validate_pat_xor_rejects_token_env_with_fullwidth_digit() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{FF11}"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["hidden character"],
    );
}

/// `token_env = "FOO.BAR"` (embedded dot) rejects via the
/// POSIX charset gate. Dot is a common shell-config typo for
/// underscore — operators sometimes write `MY.VAR` thinking
/// it's valid. The regex anchors charset to `[A-Za-z0-9_]` so
/// dot fails.
#[test]
fn validate_pat_xor_rejects_token_env_with_dot() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO.BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env = "FOO$BAR"` (embedded dollar) rejects via
/// the POSIX charset gate. Dollar is the shell variable
/// expansion sigil — operators sometimes paste the SHELL
/// REFERENCE form instead of the NAME. Pinned so the gate
/// catches this common shape.
#[test]
fn validate_pat_xor_rejects_token_env_with_dollar() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO$BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &[],
    );
}

// -------- Mn-class combining-mark rejection ------------------------

/// `is_disallowed_hidden_char(U+0300)` (COMBINING GRAVE
/// ACCENT, general category Mn — Mark, nonspacing) returns
/// true via the Mn-class arm. Without this arm only the explicit
/// listed Mn codepoints (CGJ U+034F, variation selectors
/// U+FE00..=U+FE0F) rejected; arbitrary combining marks like
/// U+0300..=U+036F passed through. Pinned to catch a regression
/// that drops the `GeneralCategory` check.
#[test]
fn is_disallowed_hidden_char_rejects_combining_grave_accent() {
    assert!(is_disallowed_hidden_char('\u{0300}'));
}

/// `is_disallowed_hidden_char(U+0301)` (COMBINING ACUTE
/// ACCENT, also Mn) returns true. Pinned alongside U+0300 so
/// the property is exercised at both ends of the
/// combining-diacritical-marks block (U+0300..=U+036F).
#[test]
fn is_disallowed_hidden_char_rejects_combining_acute_accent() {
    assert!(is_disallowed_hidden_char('\u{0301}'));
}

/// `is_disallowed_hidden_char('a')` returns false — base
/// ASCII letters are not Mn, not Cc, not in the explicit list.
/// Negative pin so a regression that broadens the
/// general-category check (e.g. accidentally rejects all
/// `Mark` rather than `NonspacingMark`) is caught.
#[test]
fn is_disallowed_hidden_char_accepts_ascii_letter() {
    assert!(!is_disallowed_hidden_char('a'));
}

/// `is_disallowed_hidden_char(U+00E0)` (LATIN SMALL LETTER
/// A WITH GRAVE, the precomposed NFC form of `a + U+0300`)
/// returns false. U+00E0 is `Ll` (Letter, lowercase) — NOT Mn —
/// so the precomposed form is safe to use in
/// internationalized config paths. Pinned so the doc-comment
/// claim "operators with internationalized paths should use
/// precomposed (NFC) forms" is empirically grounded.
#[test]
fn is_disallowed_hidden_char_accepts_precomposed_a_grave() {
    assert!(!is_disallowed_hidden_char('\u{00E0}'));
}

/// `token_file = "pa\u{0300}t"` (path containing a base
/// `t` overlaid with COMBINING GRAVE ACCENT) rejects via the
/// hidden-char gate. The Mn arm catches the U+0300 codepoint;
/// without the Mn-class arm this would flow through every shape gate
/// because `is_control()` doesn't catch combining marks and
/// the explicit list doesn't cover the generic combining-
/// diacriticals block. The diagnostic is the
/// dedicated "combining mark" + "precomposed (NFC)" form, not
/// the generic "hidden character" framing — pinned alongside
/// codepoint + byte offset so a regression that reverts the
/// Mn-specific branch surfaces here.
#[test]
fn validate_pat_xor_rejects_token_file_with_combining_mark() {
    let cfg = cfg_with_pat_auth("pat", None, Some("pa\u{0300}t"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+0300",
            "byte offset",
            "precomposed",
            "NFC",
        ],
        &["/etc/ghars/pat"],
        &["hidden character"],
    );
}

/// Regression pin — CGJ (U+034F COMBINING GRAPHEME JOINER)
/// is rejected via the Mn-class arm of
/// `is_disallowed_hidden_char`. There is no explicit codepoint
/// listing for U+034F, so the Mn arm is the only line of
/// defense. If the `unicode-general-category` crate ever
/// misclassifies U+034F (e.g. via a UCD-table regeneration
/// bug), this test surfaces the regression.
#[test]
fn is_disallowed_hidden_char_rejects_combining_grapheme_joiner() {
    assert!(is_disallowed_hidden_char('\u{034F}'));
}

/// Regression pin — VS-16 (U+FE0F VARIATION SELECTOR-16,
/// the emoji variant selector) is rejected via the Mn-class
/// arm of `is_disallowed_hidden_char`. There is no explicit
/// codepoint listing for U+FE0F, so the Mn arm is the only
/// line of defense. If the unicode-general-category crate
/// ever misclassifies U+FE0F, this test surfaces it.
#[test]
fn is_disallowed_hidden_char_rejects_variation_selector() {
    assert!(is_disallowed_hidden_char('\u{FE0F}'));
}

/// Negative pin — U+0903 DEVANAGARI SIGN VISARGA is Mc
/// (`Spacing_Mark`), NOT Mn. Defends against accidentally
/// broadening the check to all Mark class (Mn+Mc+Me). Without
/// this pin a future regression that swaps the
/// `GeneralCategory::NonspacingMark` check for a generic
/// `Mark` predicate would silently start rejecting legitimate
/// internationalized scripts that rely on spacing marks.
#[test]
fn is_disallowed_hidden_char_accepts_spacing_mark() {
    assert!(!is_disallowed_hidden_char('\u{0903}'));
}

// -------- validate_auth_keys tests ---------------------------------

/// A properly-shaped auth key (matches `IDENTIFIER_REGEX`:
/// lowercase letters + digits + dashes, starts with letter,
/// ends with letter/digit) MUST pass `validate_auth_keys`. The
/// canonical "pat" key from `cfg_with_runner_trust_zone` is the
/// happy-path pin.
#[test]
fn validate_auth_keys_accepts_canonical_pat() {
    let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    validate_auth_keys(&cfg).expect("canonical 'pat' auth key must pass");
}

/// An auth key matching the kebab-case identifier shape
/// (multi-segment with internal dashes) MUST pass. Pinned so
/// the regex `^[a-z]([a-z0-9-]*[a-z0-9])?$` is exercised at the
/// multi-segment boundary, not just the single-word case.
#[test]
fn validate_auth_keys_accepts_kebab_case_multi_segment() {
    let cfg = cfg_with_pat_auth("alpha-zone-creds", Some("GHARS_PAT"), None);
    validate_auth_keys(&cfg).expect("kebab-case multi-segment auth key must pass");
}

/// An auth key with an underscore (e.g. "`alpha_zone_creds`")
/// rejects via `validate_identifier` — `IDENTIFIER_REGEX` is
/// kebab-only (`[a-z0-9-]`), no underscores. Operators
/// migrating from `snake_case` TOML conventions need a clear
/// rejection rather than a confusing apply-time error.
#[test]
fn validate_auth_keys_rejects_underscore() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "alpha_zone_creds".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("underscore must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("auth \"alpha_zone_creds\""),
                "msg must scope to auth key; got: {msg}"
            );
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from validate_identifier; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// An auth key with an uppercase letter rejects.
/// `IDENTIFIER_REGEX` is lowercase-only.
#[test]
fn validate_auth_keys_rejects_uppercase() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "PAT".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("uppercase auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// An auth key starting with a dash rejects.
/// `IDENTIFIER_REGEX` requires a leading letter.
#[test]
fn validate_auth_keys_rejects_dash_leading() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("dash-leading auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// An empty auth key rejects via the empty-input arm of
/// `validate_identifier`. TOML allows empty quoted keys
/// (`[auth.""]`), so this is reachable from operator input.
#[test]
fn validate_auth_keys_rejects_empty() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        String::new(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("empty auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// An auth key with embedded whitespace rejects. Pinned
/// to catch the case where TOML's quoted-key syntax allows
/// `[auth."FOO BAR"]` as a literal string but the validator
/// still surfaces a clear rejection.
#[test]
fn validate_auth_keys_rejects_embedded_whitespace() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "foo bar".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("whitespace in auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// `validate_auth_keys` walks every entry. When the first
/// entry passes and the second fails, the validator surfaces
/// the second's error. Pinned to catch a regression that early-
/// returns on the first entry (only checking entry 0).
#[test]
fn validate_auth_keys_walks_past_valid_to_invalid() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "good-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    cfg.auth.insert(
        "bad_pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("second invalid auth key must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("auth \"bad_pat\""),
                "must scope to second key; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// `Load_config` integration pin: a TOML config that has a
/// shape-valid `[auth.NAME]` Pat block but uses a quoted key
/// containing whitespace (`[auth."bad key"]`) MUST reject at
/// `load_config` time via the `validate_auth_keys` gate, BEFORE the
/// downstream `validate_pat_xor` gate ever runs. Pinned end-to-end
/// (file → `load_config` → first failing validator) because
/// `load_config` is the single chokepoint that every CLI subcommand
/// (`cmd_validate`, `cmd_plan`, `cmd_apply`, `cmd_status`, `cmd_add`) routes
/// through; a regression that drops `validate_auth_keys` from the
/// `load_config` sequence would silently accept hostile keys at all
/// five callsites at once. The Pat block's `token_env` is shape-valid
/// (`GHARS_PAT` passes POSIX charset and hidden-char gates) so the
/// rejection here can ONLY come from `validate_auth_keys` — proves
/// `load_config` wiring order.
#[test]
fn load_config_rejects_auth_key_with_space_before_pat_xor_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // Quoted key syntax: TOML accepts `[auth."bad key"]` as a
    // literal string key with embedded whitespace. The Pat block
    // is otherwise valid (token_env = "GHARS_PAT" passes every
    // validate_pat_xor gate).
    let body = "\
[defaults]

[auth.\"bad key\"]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/owner/repo\"
auth = \"bad key\"
";
    fs::write(config_path.as_std_path(), body).unwrap();
    let err = load_config(&config_path).expect_err("space-bearing auth key must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("auth \"bad key\""),
                "msg must scope to the offending auth key; got: {msg}"
            );
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from validate_identifier (validate_auth_keys), \
                 not validate_pat_xor; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

// -------- cache pool name validation --------------------------------

/// Pins (a) `validate_cache_pool_names` returns a Validation error
/// scoped to the offending pool, (b) the rejection reaches the
/// identifier-shape gate, and (c) Validation maps to exit code 6
/// via `err_to_exit_code`. Wire-up at `cmd_validate` / `cmd_plan` /
/// `cmd_apply` is structurally verified by code review; end-to-end
/// integration coverage is pending in the `cmd_validate` / `cmd_plan`
/// / `cmd_apply` integration suite.
#[test]
fn validate_cache_pool_names_rejects_oversize_pool_with_exit_code_six() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    let pool_name = "a".repeat(crate::config::IDENTIFIER_MAX_LEN + 1);
    cfg.cache_pools.insert(
        pool_name.clone(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let err = validate_cache_pool_names(&cfg).expect_err("oversize pool name must reject");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool") && msg.contains(&pool_name),
                "msg must scope to the offending cache_pool by name; got: {msg}"
            );
            assert!(
                msg.contains("identifier") && msg.contains("too long"),
                "msg must come from the identifier-shape gate; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// Acceptance boundary: a runner.caches entry whose length
/// exactly equals `IDENTIFIER_MAX_LEN` must pass — and the same
/// name as a `cache_pools` key must also pass. Pins the
/// inclusive-of-cap contract so a future tightening of the
/// identifier cap (e.g. accidental change to `<` instead of `<=`)
/// is caught by this test rather than by an operator hitting a
/// previously-valid config.
#[test]
fn validate_cache_pool_names_accepts_runner_caches_at_max_len() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    let at_max = "a".repeat(crate::config::IDENTIFIER_MAX_LEN);
    // Both the cache_pools key AND the runner.caches reference use
    // the same MAX_LEN string — this exercises both inner loops in
    // validate_cache_pool_names.
    cfg.cache_pools.insert(
        at_max.clone(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    cfg.runners[0].caches = vec![at_max.clone()];
    validate_cache_pool_names(&cfg).unwrap_or_else(|e| {
        panic!(
            "{}-char (== IDENTIFIER_MAX_LEN) cache name must accept; got: {e}",
            crate::config::IDENTIFIER_MAX_LEN
        )
    });
}

// ---- validate_cache_pool_binary_paths -----------------------------------

/// Pins the config-load gate: a relative `sccache_path` must reject
/// with a Validation error scoped to the offending pool by name.
/// Without this gate the plan-time resolver still rejects the bad
/// path, but the operator sees the error one phase later (after
/// per-pool name + `trust_zone` validations) and without the
/// `cache_pool "NAME":` scope prefix.
#[test]
fn validate_cache_pool_binary_paths_rejects_relative_sccache_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "build".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("relative/sccache".into()),
            sleep_path: None,
        },
    );
    let err =
        validate_cache_pool_binary_paths(&cfg).expect_err("relative sccache_path must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool \"build\"") && msg.contains("sccache_path"),
                "msg must scope to the offending pool by name and field; got: {msg}"
            );
            assert!(
                msg.contains("absolute"),
                "msg must name the absolute-path requirement; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// Symmetric to the `sccache_path` test: relative `sleep_path` must
/// reject at config load with the same scope prefix.
#[test]
fn validate_cache_pool_binary_paths_rejects_relative_sleep_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "build".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("relative/sleep".into()),
        },
    );
    let err = validate_cache_pool_binary_paths(&cfg).expect_err("relative sleep_path must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool \"build\"") && msg.contains("sleep_path"),
                "msg must scope to the offending pool by name and field; got: {msg}"
            );
            assert!(
                msg.contains("absolute"),
                "msg must name the absolute-path requirement; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// Absolute paths must pass — the gate is opt-in (None) and absolute
/// pins. This pins the accept path so a future tightening (e.g.
/// rejecting symlinks, or enforcing a `starts_with(/usr)` constraint)
/// is caught here rather than silently breaking valid configs.
#[test]
fn validate_cache_pool_binary_paths_accepts_absolute_pins_and_none() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // Pool 1: both fields pinned absolutely.
    cfg.cache_pools.insert(
        "pinned".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/opt/sccache/bin/sccache".into()),
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    // Pool 2: both fields None (auto-detect at plan time).
    cfg.cache_pools.insert(
        "auto".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "100G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: None,
        },
    );
    validate_cache_pool_binary_paths(&cfg).expect("absolute pins + None must pass");
}

// ---- pat_for_url / runner_pat / pat_for_auth_name -----------------------

fn make_cfg_with_runner(auth_name: Option<&str>, defaults_auth: Option<&str>) -> Config {
    use crate::config::{AuthSpec, Defaults, RunnerSpec};
    let mut cfg = Config {
        defaults: Defaults {
            auth: defaults_auth.map(String::from),
            ..Defaults::default()
        },
        ..Config::default()
    };
    let runner = RunnerSpec {
        environment: crate::config::EnvironmentSpec::default(),
        name: "buckos".into(),
        count: None,
        url: "https://github.com/example/repo".into(),
        auth: auth_name.map(String::from),
        labels: Vec::new(),
        memory_max: None,
        runner_version: None,
        runner_sha256: None,
        runner_tarball: None,
        arch: None,
        caches: Vec::new(),
        trust_zone: "default".into(),
        network: None,
        proxy: None,
        hooks: None,
        hardening: crate::config::Hardening::default(),
        allowed_cpus: None,
        allowed_memory_nodes: None,
    };
    cfg.runners.push(runner);
    cfg.auth.insert(
        "pat-explicit".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_TEST_RUNNER_PAT_EXPLICIT".into()),
            token_file: None,
        },
    );
    cfg.auth.insert(
        "pat-default".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_TEST_RUNNER_PAT_DEFAULT".into()),
            token_file: None,
        },
    );
    cfg
}

#[test]
fn runner_pat_uses_per_runner_auth_when_set() {
    if env::set_var("GHARS_TEST_RUNNER_PAT_EXPLICIT", "explicit-token").is_none() {
        return;
    }
    let cfg = make_cfg_with_runner(Some("pat-explicit"), Some("pat-default"));
    let pat = runner_pat(&cfg, &cfg.runners[0]);
    assert_eq!(pat, Some("explicit-token".into()));
    let _ = env::remove_var("GHARS_TEST_RUNNER_PAT_EXPLICIT");
}

#[test]
fn runner_pat_falls_back_to_defaults_auth() {
    if env::set_var("GHARS_TEST_RUNNER_PAT_DEFAULT", "default-token").is_none() {
        return;
    }
    let cfg = make_cfg_with_runner(None, Some("pat-default"));
    let pat = runner_pat(&cfg, &cfg.runners[0]);
    assert_eq!(pat, Some("default-token".into()));
    let _ = env::remove_var("GHARS_TEST_RUNNER_PAT_DEFAULT");
}

#[test]
fn runner_pat_returns_none_when_neither_auth_set() {
    let cfg = make_cfg_with_runner(None, None);
    let pat = runner_pat(&cfg, &cfg.runners[0]);
    assert_eq!(pat, None);
}

#[test]
fn pat_for_url_finds_first_runner_matching_url() {
    if env::set_var("GHARS_TEST_RUNNER_PAT_EXPLICIT", "url-matched-token").is_none() {
        return;
    }
    let cfg = make_cfg_with_runner(Some("pat-explicit"), None);
    let pat = pat_for_url(&cfg, "https://github.com/example/repo");
    assert_eq!(pat, Some("url-matched-token".into()));
    let _ = env::remove_var("GHARS_TEST_RUNNER_PAT_EXPLICIT");
}

#[test]
fn pat_for_url_returns_none_for_unmatched_url() {
    let cfg = make_cfg_with_runner(Some("pat-explicit"), None);
    let pat = pat_for_url(&cfg, "https://github.com/other/repo");
    assert_eq!(pat, None);
}

// ---- render_metrics_text / render_metrics_json --------------------------

fn metric_row(name: &str, mem: u64, cpu: u64, ior: u64, iow: u64, tasks: u64) -> MetricRow {
    MetricRow {
        name: name.into(),
        memory_bytes: mem,
        cpu_nsec: cpu,
        io_read_bytes: ior,
        io_write_bytes: iow,
        tasks,
    }
}

#[test]
fn render_metrics_text_emits_header_and_row() {
    let rows = vec![metric_row("alpha", 4 * 1024 * 1024, 1_000_000, 0, 0, 5)];
    let mut out: Vec<u8> = Vec::new();
    render_metrics_text(&mut out, &rows, false).expect("render must succeed");
    let s = String::from_utf8(out).unwrap();
    assert!(
        s.contains("name") && s.contains("memory") && s.contains("cpu_nsec"),
        "header missing: {s:?}",
    );
    assert!(s.contains("alpha"), "row name missing: {s:?}");
    assert!(s.contains("4.0 MiB"), "memory binary unit missing: {s:?}");
}

#[test]
fn render_metrics_text_emits_total_when_multiple_rows() {
    let rows = vec![
        metric_row("a", 1024, 100, 0, 0, 1),
        metric_row("b", 1024, 200, 0, 0, 2),
    ];
    let mut out: Vec<u8> = Vec::new();
    render_metrics_text(&mut out, &rows, false).expect("render must succeed");
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("TOTAL"), "TOTAL row missing: {s:?}");
    // memory total = 2048 → "2.0 KiB"
    assert!(
        s.contains("2.0 KiB"),
        "saturating-sum total must use binary units; got: {s:?}"
    );
}

#[test]
fn render_metrics_text_suppresses_total_with_no_total_flag() {
    let rows = vec![
        metric_row("a", 1024, 100, 0, 0, 1),
        metric_row("b", 1024, 200, 0, 0, 2),
    ];
    let mut out: Vec<u8> = Vec::new();
    render_metrics_text(&mut out, &rows, true).expect("render must succeed");
    let s = String::from_utf8(out).unwrap();
    assert!(
        !s.contains("TOTAL"),
        "--no-total must suppress TOTAL: {s:?}"
    );
}

#[test]
fn render_metrics_text_skips_total_for_single_row() {
    let rows = vec![metric_row("only", 1024, 100, 0, 0, 1)];
    let mut out: Vec<u8> = Vec::new();
    render_metrics_text(&mut out, &rows, false).expect("render must succeed");
    let s = String::from_utf8(out).unwrap();
    assert!(
        !s.contains("TOTAL"),
        "single-row table omits TOTAL even without --no-total: {s:?}"
    );
}

#[test]
fn render_metrics_text_saturates_on_overflow() {
    // Two rows each at u64::MAX/2 + 1 would overflow u64 sum without
    // saturating_add. saturating_add caps at u64::MAX instead of panicking.
    let rows = vec![
        metric_row("a", u64::MAX, 0, 0, 0, 0),
        metric_row("b", 100, 0, 0, 0, 0),
    ];
    let mut out: Vec<u8> = Vec::new();
    render_metrics_text(&mut out, &rows, false).expect("render must not panic on overflow");
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("TOTAL"));
}
