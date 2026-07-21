"""Redacted-secret type + redaction helpers — defense-in-depth so secrets never leak.

Written first (RED). The module ``agentforge.secrets`` does not exist yet, so import fails
=> RED for the right reason.

Contract under test (framework-neutral, stdlib only):

* ``Secret`` wraps a raw string. ``repr``, ``str``, ``format``, f-strings, and ``%``-format
  ALL return a fixed redaction marker and NEVER the raw value — so logging, error messages,
  and traces cannot leak it. ``.reveal()`` is the ONLY way to obtain the raw value.
  ``__eq__`` compares wrapped values without exposing them; ``__hash__`` is consistent for
  equal values; ``__bool__`` reflects the wrapped value's truthiness.
* ``redact_mapping(data)`` returns a copy where a ``Secret`` value is replaced by its marker
  AND any key whose lowercased name contains a sensitive hint is masked, while a
  non-sensitive key is left intact.
* ``looks_like_provider_key(s)`` — a SECONDARY backstop — detects known provider key prefixes.

Every value used here is a FAKE sentinel; no real-looking captured key appears.
"""

from __future__ import annotations

from agentforge.secrets import Secret, looks_like_provider_key, redact_mapping

# Fake sentinels only — never a real key.
FAKE_SECRET = "sentinel-shh-123"
FAKE_SK = "sk-FAKE-not-real-000"
FAKE_SK_OR = "sk-or-FAKE-not-real-000"
FAKE_SK_ANT = "sk-ant-FAKE-not-real-000"


# ---------------------------------------------------------------------------
# Secret — stringification always redacts, never leaks the raw value
# ---------------------------------------------------------------------------


def test_repr_excludes_raw_value() -> None:
    """repr(Secret(s)) shows a redaction marker and NEVER the raw sentinel."""
    secret = Secret(FAKE_SECRET)
    rendered = repr(secret)
    assert FAKE_SECRET not in rendered
    assert "REDACTED" in rendered


def test_str_excludes_raw_value() -> None:
    """str(Secret(s)) shows a redaction marker and NEVER the raw sentinel."""
    secret = Secret(FAKE_SECRET)
    rendered = str(secret)
    assert FAKE_SECRET not in rendered
    assert "REDACTED" in rendered


def test_format_excludes_raw_value() -> None:
    """format(Secret(s), spec) shows a redaction marker and NEVER the raw sentinel."""
    secret = Secret(FAKE_SECRET)
    rendered = format(secret, "")
    assert FAKE_SECRET not in rendered
    assert "REDACTED" in rendered


def test_fstring_excludes_raw_value() -> None:
    """An f-string interpolation of a Secret redacts and NEVER leaks the raw sentinel."""
    secret = Secret(FAKE_SECRET)
    rendered = f"{secret}"
    assert FAKE_SECRET not in rendered
    assert "REDACTED" in rendered


def test_percent_format_excludes_raw_value() -> None:
    """A ``%s`` interpolation of a Secret redacts and NEVER leaks the raw sentinel."""
    secret = Secret(FAKE_SECRET)
    # Percent-format is deliberate here: %-style logging (logger.info("%s", secret)) must
    # also redact, so we assert on that exact interpolation path rather than an f-string.
    rendered = "%s" % secret  # noqa: UP031 - exercising %-format redaction is the point
    assert FAKE_SECRET not in rendered
    assert "REDACTED" in rendered


# ---------------------------------------------------------------------------
# Secret — reveal() is the ONLY way out; equality/hash/bool behave sanely
# ---------------------------------------------------------------------------


def test_reveal_returns_raw_value() -> None:
    """.reveal() returns the raw value at the authorized call boundary."""
    assert Secret(FAKE_SECRET).reveal() == FAKE_SECRET


def test_equal_values_are_equal() -> None:
    """Two Secrets wrapping equal values compare equal without exposing them."""
    assert Secret(FAKE_SECRET) == Secret(FAKE_SECRET)


def test_unequal_values_are_not_equal() -> None:
    """Two Secrets wrapping different values compare unequal."""
    assert Secret(FAKE_SECRET) != Secret("a-different-sentinel-456")


def test_hash_is_consistent_for_equal_values() -> None:
    """Equal Secrets hash equally, so they behave in sets/dicts."""
    assert hash(Secret(FAKE_SECRET)) == hash(Secret(FAKE_SECRET))
    assert len({Secret(FAKE_SECRET), Secret(FAKE_SECRET)}) == 1


def test_bool_reflects_wrapped_truthiness() -> None:
    """__bool__ reflects the wrapped value: non-empty is truthy, empty is falsy."""
    assert bool(Secret(FAKE_SECRET)) is True
    assert bool(Secret("")) is False


# ---------------------------------------------------------------------------
# redact_mapping — masks Secret values and sensitive-looking keys
# ---------------------------------------------------------------------------


def test_redact_mapping_masks_secret_value() -> None:
    """A Secret value in a mapping is replaced by its redaction marker, not its raw value."""
    redacted = redact_mapping({"provider_key": Secret(FAKE_SECRET)})
    assert FAKE_SECRET not in str(redacted)
    assert "REDACTED" in str(redacted["provider_key"])


def test_redact_mapping_masks_sensitive_keys() -> None:
    """A plain string under a sensitive-looking key is masked, not carried through in the clear."""
    data = {
        "api_key": FAKE_SK,
        "OPENROUTER_API_KEY": FAKE_SK_OR,
        "session_cookie": FAKE_SECRET,
    }
    redacted = redact_mapping(data)
    assert redacted["api_key"] != FAKE_SK
    assert redacted["OPENROUTER_API_KEY"] != FAKE_SK_OR
    assert redacted["session_cookie"] != FAKE_SECRET
    assert FAKE_SK not in str(redacted)
    assert FAKE_SK_OR not in str(redacted)
    assert FAKE_SECRET not in str(redacted)


def test_redact_mapping_leaves_non_sensitive_keys_intact() -> None:
    """A non-sensitive key (e.g. ``environment``) passes through unchanged."""
    redacted = redact_mapping({"environment": "local"})
    assert redacted["environment"] == "local"


# ---------------------------------------------------------------------------
# redact_mapping — DEEP: a sensitive key/Secret at ANY depth must not leak
# (config becomes nested the moment M4/M8/M9 log agent lists / provider sub-maps;
#  a shallow pass would leak a plain sensitive string one level down)
# ---------------------------------------------------------------------------


def test_redact_mapping_masks_plain_sensitive_string_nested_in_subdict() -> None:
    """A plain (unwrapped) sensitive string one level down must NOT survive in the clear.

    This is the real leak vector a shallow redactor misses: the Secret type protects itself
    via its own repr, but a raw string under a sensitive key in a sub-mapping would otherwise
    pass through. Deep redaction closes it — and the caller's original is not mutated.
    """
    data = {"provider": {"api_key": FAKE_SK}}
    redacted = redact_mapping(data)
    assert FAKE_SK not in str(redacted)
    assert data["provider"]["api_key"] == FAKE_SK  # original untouched


def test_redact_mapping_masks_secret_nested_in_subdict() -> None:
    """A Secret nested in a sub-mapping is redacted at depth."""
    redacted = redact_mapping({"judge": {"session_cookie": Secret(FAKE_SECRET)}})
    assert FAKE_SECRET not in str(redacted)


def test_redact_mapping_masks_sensitive_value_in_list_of_dicts() -> None:
    """A sensitive value nested inside a list of mappings must not leak; siblings survive."""
    data = {"agents": [{"name": "red-team", "api_key": FAKE_SK_OR}]}
    redacted = redact_mapping(data)
    assert FAKE_SK_OR not in str(redacted)
    assert "red-team" in str(redacted)  # non-sensitive sibling passes through


# ---------------------------------------------------------------------------
# looks_like_provider_key — SECONDARY backstop, never raises
# ---------------------------------------------------------------------------


def test_looks_like_provider_key_detects_known_prefixes() -> None:
    """Detects fake ``sk-`` / ``sk-or-`` / ``sk-ant-`` sentinels."""
    assert looks_like_provider_key(FAKE_SK) is True
    assert looks_like_provider_key(FAKE_SK_OR) is True
    assert looks_like_provider_key(FAKE_SK_ANT) is True


def test_looks_like_provider_key_false_for_ordinary_string() -> None:
    """An ordinary, non-key string is not flagged."""
    assert looks_like_provider_key("just an ordinary value") is False
