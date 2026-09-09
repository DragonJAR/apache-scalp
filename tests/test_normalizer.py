from scalp.core.normalizer import PayloadNormalizer

def test_url_decoding_preserves_quotes_and_spaces():
    raw = "id=1%27%20OR%201=1--"
    normalized = PayloadNormalizer.normalize(raw)
    assert normalized == "id=1' OR 1=1--"
    assert "%00" not in normalized

def test_path_traversal_decoding():
    raw = "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    normalized = PayloadNormalizer.normalize(raw)
    assert "../../etc/passwd" in normalized

def test_recursive_double_encoding():
    raw = "q=%2522%253E%253Cscript%253E"
    normalized = PayloadNormalizer.normalize(raw)
    assert '"><script>' in normalized

def test_html_entity_decoding():
    raw = "search=&lt;svg/onload=alert(1)&gt;"
    normalized = PayloadNormalizer.normalize(raw)
    assert "<svg/onload=alert(1)>" in normalized

def test_null_byte_removal():
    raw = "page=profile.php%00.jpg\x00"
    normalized = PayloadNormalizer.normalize(raw)
    assert "\x00" not in normalized

def test_malformed_percent_encoding_does_not_crash():
    raw = "test=%zz%a%1"
    normalized = PayloadNormalizer.normalize(raw)
    assert "test=" in normalized
