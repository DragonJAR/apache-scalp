"""Multi-stage payload normalizer and decoder for anti-evasion detection."""
import base64
import html
import unicodedata
import urllib.parse
import regex as re

BASE64_PATTERN = re.compile(
    r'(?:base64,(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?|(?:cmd|code|data|payload|exec)=([A-Za-z0-9+/]{12,}={0,2}))',
    re.IGNORECASE,
)
CONTROL_CHARS_PATTERN = re.compile(r'[\x01-\x08\x0b\x0c\x0e-\x1f]')


class PayloadNormalizer:
    """Normalizes URL payloads to defeat evasion techniques such as double-encoding,
    HTML entity encoding, Unicode fullwidth variants, and null-byte injection."""

    @staticmethod
    def normalize(text: str, max_iterations: int = 3) -> str:
        """Applies multi-pass URL decoding, HTML entity unescaping, Unicode NFKC normalization,
        and null-byte stripping."""
        if not text:
            return ""

        current = text

        # Recursive URL decoding (up to max_iterations) to catch double/triple encoding
        for _ in range(max_iterations):
            try:
                unquoted = urllib.parse.unquote_plus(current)
            except Exception:
                break

            if unquoted == current:
                break
            current = unquoted

        # HTML entity unescaping (&quot;, &#x27;, &lt;, etc.)
        try:
            current = html.unescape(current)
        except Exception:
            pass

        # Unicode NFKC normalization (converts fullwidth chars like '／', '＼', '＜', '＞' to standard ASCII)
        try:
            current = unicodedata.normalize("NFKC", current)
        except Exception:
            pass

        # Strip null bytes and non-printable control characters
        current = current.replace("\x00", "").replace("%00", "")
        current = CONTROL_CHARS_PATTERN.sub("", current)

        # Base64 payload extraction (e.g. data:...,base64,... or ?cmd=base64string)
        try:
            for match in BASE64_PATTERN.finditer(current):
                b64_str = (
                    match.group(1)
                    if match.lastindex and match.group(1)
                    else match.group(0).split("base64,")[-1]
                )
                if b64_str and len(b64_str) >= 8:
                    try:
                        pad = len(b64_str) % 4
                        if pad:
                            b64_str += "=" * (4 - pad)
                        decoded_bytes = base64.b64decode(b64_str, validate=False)
                        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                        if decoded_text and any(c.isalnum() for c in decoded_text):
                            current += f" [b64:{decoded_text}]"
                    except Exception:
                        pass
        except Exception:
            pass

        return current
