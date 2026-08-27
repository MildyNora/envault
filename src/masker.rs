use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

const MIN_MASK_LEN: usize = 6;

pub struct Masker {
    /// (pattern bytes, replacement bytes), longest pattern first
    patterns: Vec<(Vec<u8>, Vec<u8>)>,
    buf: Vec<u8>,
    holdback: usize,
}

impl Masker {
    pub fn new(secrets: &[(String, String)]) -> Masker {
        let mut patterns: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (alias, value) in secrets {
            if value.len() < MIN_MASK_LEN {
                continue;
            }
            let replacement = format!("[envault:{alias}]").into_bytes();
            let mut forms = vec![value.clone().into_bytes(), B64.encode(value).into_bytes()];
            let url = urlencoding::encode(value).into_owned().into_bytes();
            if url != value.as_bytes() {
                forms.push(url);
            }
            for f in forms {
                patterns.push((f, replacement.clone()));
            }
        }
        // longest first, so a longer form wins when forms overlap
        patterns.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        let holdback = patterns
            .iter()
            .map(|(p, _)| p.len())
            .max()
            .map_or(0, |m| m - 1);
        Masker {
            patterns,
            buf: Vec::new(),
            holdback,
        }
    }

    /// Replace every full pattern occurrence currently in the buffer.
    /// Skips past inserted replacement text so replacements are never re-scanned,
    /// and a pattern can never span the emit boundary because `holdback` is at
    /// least every pattern length minus one.
    fn replace_in_buf(&mut self) {
        let mut i = 0;
        'outer: while i < self.buf.len() {
            for pat_idx in 0..self.patterns.len() {
                let (pat, rep) = &self.patterns[pat_idx];
                if self.buf[i..].starts_with(pat) {
                    let rep = rep.clone();
                    let pat_len = pat.len();
                    self.buf.splice(i..i + pat_len, rep.iter().copied());
                    i += rep.len();
                    continue 'outer;
                }
            }
            i += 1;
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        self.replace_in_buf();
        if self.buf.len() <= self.holdback {
            return Vec::new();
        }
        let emit_len = self.buf.len() - self.holdback;
        let out: Vec<u8> = self.buf.drain(..emit_len).collect();
        out
    }

    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
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
}
