"""JCS (RFC 8785 subset) tests: ordering, escaping, type and range errors."""

import hashlib

import pytest

from roe_guard.jcs import canonicalize

RFC_ORDERING = {
    "€": "Euro Sign",
    "\r": "Carriage Return",
    "דּ": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\U0001f600": "Emoji: Grinning Face",
    "\u0080": "Control",
    "ö": "Latin Small Letter O With Diaeresis",
}

RFC_EXPECTED_SHA = "5e321556d22018a9656991a9e94f77ec175fa193e52a2429d312f8419ec8b08c"
RFC_EXPECTED_LENGTH = 180


def test_rfc_ordering_example():
    out = canonicalize(RFC_ORDERING)
    assert hashlib.sha256(out).hexdigest() == RFC_EXPECTED_SHA
    assert len(out) == RFC_EXPECTED_LENGTH


def test_rfc_ordering_key_sequence():
    import json

    out = json.loads(canonicalize(RFC_ORDERING).decode("utf-8"))
    assert list(out) == [
        "\r",
        "1",
        "\u0080",
        "ö",
        "€",
        "\U0001f600",
        "דּ",
    ]


def test_control_char_escaped_lowercase_hex():
    out = canonicalize({"k": "\x1f"}).decode("utf-8")
    assert out == '{"k":"\\u001f"}'


def test_line_separator_stays_raw():
    out = canonicalize({"k": "\u2028"}).decode("utf-8")
    assert out == '{"k":" "}' or "\u2028" in out


def test_quote_and_backslash_escaped():
    out = canonicalize({"k": '"\\'}).decode("utf-8")
    assert out == '{"k":"\\"\\\\"}'


def test_true_false_null():
    out = canonicalize({"a": True, "b": False, "c": None}).decode("utf-8")
    assert out == '{"a":true,"b":false,"c":null}'


def test_array_order_preserved():
    out = canonicalize({"a": [3, 1, 2]}).decode("utf-8")
    assert out == '{"a":[3,1,2]}'


def test_float_rejected():
    with pytest.raises(TypeError):
        canonicalize({"x": 1.5})


def test_out_of_range_integer_rejected():
    with pytest.raises(ValueError):
        canonicalize({"x": 2**53})


def test_non_string_key_rejected():
    with pytest.raises(TypeError):
        canonicalize({1: "a"})


def test_lone_surrogate_rejected():
    with pytest.raises(ValueError):
        canonicalize({"x": "\ud800"})


def test_nesting_depth_is_bounded():
    from roe_guard.jcs import MAX_DEPTH

    deep: object = 0
    for _ in range(MAX_DEPTH):
        deep = [deep]
    assert canonicalize(deep) == b"[" * MAX_DEPTH + b"0" + b"]" * MAX_DEPTH
    with pytest.raises(ValueError):
        canonicalize([deep])
    with pytest.raises(ValueError):
        canonicalize({"k": [deep]})
    loop: list = []
    loop.append(loop)
    with pytest.raises(ValueError):
        canonicalize(loop)
