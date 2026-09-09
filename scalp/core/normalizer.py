"""Multi-stage payload normalizer and decoder for anti-evasion detection."""
import html
import urllib.parse


class PayloadNormalizer:
    """Normalizes URL payloads to defeat evasion techniques such as double-encoding,
    HTML entity encoding, and null-byte injection."""

    @staticmethod
    def normalize(text: str, max_iterations: int = 3) -> str:
        """Applies multi-pass URL decoding, HTML entity unescaping, and null-byte stripping."""
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

        # Strip null bytes and control terminators
        current = current.replace("\x00", "").replace("%00", "")

        return current
