use base64::engine::general_purpose::{
    STANDARD as B64, STANDARD_NO_PAD as B64_NP, URL_SAFE as B64U, URL_SAFE_NO_PAD as B64U_NP,
};
use base64::Engine;

const MIN_MASK_LEN: usize = 6;

fn hex(bytes: &[u8], upper: bool) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        if upper {
            s.push_str(&format!("{b:02X}"));
        } else {
            s.push_str(&format!("{b:02x}"));
        }
    }
    s
}

pub struct Masker {
    /// (pattern bytes, replacement bytes), longest pattern first
    patterns: Vec<(Vec<u8>, Vec<u8>)>,
    buf: Vec<u8>,
}

impl Masker {
    pub fn new(secrets: &[(String, String)]) -> Masker {
        let mut patterns: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (alias, value) in secrets {
            if value.len() < MIN_MASK_LEN {
                continue;
            }
            let replacement = format!("[envault:{alias}]").into_bytes();
            // Cover the common re-encodings a value might appear in. (L1)
            let mut forms: Vec<Vec<u8>> = vec![
                value.clone().into_bytes(),
                // PTY ONLCR output processing inserts CR before each LF,
                // even in an existing CRLF. Keep both forms so raw-mode
                // output is still masked without rewriting unrelated bytes.
                value.replace('\n', "\r\n").into_bytes(),
                B64.encode(value).into_bytes(),
                B64_NP.encode(value).into_bytes(),
                B64U.encode(value).into_bytes(),
                B64U_NP.encode(value).into_bytes(),
                hex(value.as_bytes(), false).into_bytes(),
                hex(value.as_bytes(), true).into_bytes(),
                urlencoding::encode(value).into_owned().into_bytes(),
            ];
            forms.sort();
            forms.dedup();
            for f in forms {
                if f.len() >= MIN_MASK_LEN {
                    patterns.push((f, replacement.clone()));
                }
            }
        }
        // longest first, so a longer form wins when forms overlap
        patterns.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        Masker {
            patterns,
            buf: Vec::new(),
        }
    }

    /// Emit every unambiguous byte from the buffered raw output.
    ///
    /// If the buffer ends while it is still a prefix of a pattern, keep it for
    /// the next chunk. This includes a full shorter pattern that is also the
    /// prefix of a longer one, preserving leftmost-longest matching regardless
    /// of where reads split. Replacements are written directly to `out`, so
    /// they are never considered input patterns.
    fn drain_ready(&mut self, eof: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut consumed = 0;

        while consumed < self.buf.len() {
            let remaining = &self.buf[consumed..];
            let mut full_match: Option<(usize, &[u8])> = None;
            let mut could_extend = false;

            for (pattern, replacement) in &self.patterns {
                if remaining.len() >= pattern.len() && remaining.starts_with(pattern) {
                    if full_match.is_none() {
                        full_match = Some((pattern.len(), replacement));
                    }
                } else if remaining.len() < pattern.len() && pattern.starts_with(remaining) {
                    could_extend = true;
                }
            }

            if could_extend && !eof {
                break;
            }
            if let Some((pattern_len, replacement)) = full_match {
                out.extend_from_slice(replacement);
                consumed += pattern_len;
            } else {
                out.push(remaining[0]);
                consumed += 1;
            }
        }

        self.buf.drain(..consumed);
        out
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        self.drain_ready(false)
    }

    pub fn flush(&mut self) -> Vec<u8> {
        self.drain_ready(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask_all(m: &mut Masker, input: &[u8]) -> String {
        let mut out = m.feed(input);
        out.extend(m.flush());
        String::from_utf8(out).unwrap()
    }

    fn one(alias: &str, value: &str) -> Masker {
        Masker::new(&[(alias.to_string(), value.to_string())])
    }

    #[test]
    fn masks_exact_value() {
        let mut m = one("openrouter", "sk-or-v1-abc123");
        assert_eq!(
            mask_all(&mut m, b"key is sk-or-v1-abc123 ok"),
            "key is [envault:openrouter] ok"
        );
    }

    #[test]
    fn masks_across_chunk_boundary() {
        let mut m = one("openrouter", "sk-or-v1-abc123");
        let mut out = m.feed(b"key is sk-or-v1");
        out.extend(m.feed(b"-abc123 ok"));
        out.extend(m.flush());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "key is [envault:openrouter] ok"
        );
    }

    #[test]
    fn overlapping_prefixes_choose_longest_across_every_chunk_boundary() {
        let short = "SYNTHETIC-PREFIX";
        let long = "SYNTHETIC-PREFIX-TAIL-9988";
        let expected = "before [envault:long] after";
        let input = format!("before {long} after");

        for split in 0..=input.len() {
            let mut m = Masker::new(&[
                ("short".to_string(), short.to_string()),
                ("long".to_string(), long.to_string()),
            ]);
            let mut out = m.feed(&input.as_bytes()[..split]);
            out.extend(m.feed(&input.as_bytes()[split..]));
            out.extend(m.flush());
            assert_eq!(String::from_utf8(out).unwrap(), expected, "split {split}");
        }
    }

    #[test]
    fn overlapping_prefixes_choose_longest_with_bytewise_feeds() {
        let long = "SYNTHETIC-PREFIX-TAIL-9988";
        let mut m = Masker::new(&[
            ("short".to_string(), "SYNTHETIC-PREFIX".to_string()),
            ("long".to_string(), long.to_string()),
        ]);
        let mut out = Vec::new();
        for byte in long.as_bytes() {
            out.extend(m.feed(&[*byte]));
        }
        out.extend(m.flush());
        assert_eq!(String::from_utf8(out).unwrap(), "[envault:long]");
    }

    #[test]
    fn overlapping_prefix_resolves_to_shorter_on_mismatch_or_eof() {
        let secrets = [
            ("short".to_string(), "SYNTHETIC-PREFIX".to_string()),
            ("long".to_string(), "SYNTHETIC-PREFIX-TAIL-9988".to_string()),
        ];
        let mut mismatch = Masker::new(&secrets);
        let mut out = mismatch.feed(b"SYNTHETIC-PREFIX?");
        out.extend(mismatch.flush());
        assert_eq!(String::from_utf8(out).unwrap(), "[envault:short]?");

        let mut eof = Masker::new(&secrets);
        let mut out = eof.feed(b"SYNTHETIC-PREFIX");
        out.extend(eof.flush());
        assert_eq!(String::from_utf8(out).unwrap(), "[envault:short]");
    }

    #[test]
    fn masks_pty_newline_forms() {
        for value in [
            "SYNTHETIC-FIRST\nSYNTHETIC-LAST",
            "SYNTHETIC-FIRST\r\nSYNTHETIC-LAST",
            "SYNTHETIC-FIRST\n\nMIDDLE\r\nSYNTHETIC-LAST\n",
        ] {
            // ONLCR inserts CR before every LF, including one preceded by CR.
            let translated = value.replace('\n', "\r\n");
            for form in [value, translated.as_str()] {
                let input = format!("before\r\n{form}|after\r\n");
                let expected = "before\r\n[envault:multiline]|after\r\n";
                for split in 0..=input.len() {
                    let mut m = one("multiline", value);
                    let mut out = m.feed(&input.as_bytes()[..split]);
                    out.extend(m.feed(&input.as_bytes()[split..]));
                    out.extend(m.flush());
                    assert_eq!(out, expected.as_bytes(), "split {split}");
                }
                let mut m = one("multiline", value);
                let mut out = Vec::new();
                for byte in input.as_bytes() {
                    out.extend(m.feed(&[*byte]));
                }
                out.extend(m.flush());
                assert_eq!(out, expected.as_bytes());
            }
        }
    }

    #[test]
    fn pty_newline_masking_preserves_unrelated_bytes() {
        let mut m = one("multiline", "SYNTHETIC-FIRST\nSYNTHETIC-LAST");
        let input = b"ordinary\ntext\r\nwith\r\r\nnewlines\r";
        let mut out = m.feed(input);
        out.extend(m.flush());
        assert_eq!(out, input);
    }

    #[test]
    fn pty_expansion_does_not_change_short_value_policy() {
        let mut m = one("short", "a\nb\nc");
        assert_eq!(mask_all(&mut m, b"a\r\nb\r\nc"), "a\r\nb\r\nc");
    }

    #[test]
    fn masks_base64_form() {
        // echo -n 'sk-or-v1-abc123' | base64  ->  c2stb3ItdjEtYWJjMTIz
        let mut m = one("openrouter", "sk-or-v1-abc123");
        assert_eq!(
            mask_all(&mut m, b"b64: c2stb3ItdjEtYWJjMTIz."),
            "b64: [envault:openrouter]."
        );
    }

    #[test]
    fn masks_url_encoded_form() {
        let mut m = one("weird", "p@ss word+1");
        assert_eq!(
            mask_all(&mut m, b"q=p%40ss%20word%2B1&x=1"),
            "q=[envault:weird]&x=1"
        );
    }

    #[test]
    fn short_values_not_masked() {
        let mut m = one("pin", "1234");
        assert_eq!(mask_all(&mut m, b"pin is 1234"), "pin is 1234");
    }

    #[test]
    fn multiple_secrets_and_repeats() {
        let mut m = Masker::new(&[
            ("a-key".to_string(), "AAAAAA".to_string()),
            ("b-key".to_string(), "BBBBBB".to_string()),
        ]);
        assert_eq!(
            mask_all(&mut m, b"AAAAAA BBBBBB AAAAAA"),
            "[envault:a-key] [envault:b-key] [envault:a-key]"
        );
    }

    #[test]
    fn no_secrets_passthrough_without_holdback() {
        let mut m = Masker::new(&[]);
        assert_eq!(m.feed(b"hello"), b"hello".to_vec());
        assert!(m.flush().is_empty());
    }

    #[test]
    fn partial_match_at_eof_is_emitted_by_flush() {
        let mut m = one("openrouter", "sk-or-v1-abc123");
        let mut out = m.feed(b"tail sk-or-v1");
        out.extend(m.flush());
        assert_eq!(String::from_utf8(out).unwrap(), "tail sk-or-v1");
    }

    #[test]
    fn nonmatching_short_prompt_is_emitted_immediately() {
        let mut m = one("long", "SYNTHETIC-SECRET-PROMPT-9988");
        assert_eq!(m.feed(b"Password: "), b"Password: ");
        assert!(m.flush().is_empty());
    }

    #[test]
    fn prompt_only_holds_a_trailing_secret_prefix() {
        let mut m = one("long", "SYNTHETIC-SECRET-PROMPT-9988");
        assert_eq!(m.feed(b"Password: SYNTHETIC-SEC"), b"Password: ");
        assert_eq!(m.flush(), b"SYNTHETIC-SEC");
    }
}
