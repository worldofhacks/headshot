"""WP-16C — the LLM workbench Decoder: real, offline encoding-bypass transforms.

The workbench declared a Decoder ("PyRIT converters: Base64, ROT13, ASCII-smuggling") but had no
transform function. This module makes it a real capability: it turns an attack turn into an encoded
variant that tests whether an encoding slips past the target's input guardrails. Each transform is
content-addressed (a digest of transform + input + output) so the produced candidate is traceable
and pinnable, matching the tool-candidate provenance model.

Transforms are a pure function of their input — offline, deterministic, no model, no network. The
output is UNTRUSTED candidate input only; it carries no verdict and dispatches (if at all) through
the Policy Gateway like any other candidate.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import json
from dataclasses import dataclass
from urllib.parse import quote

MAX_DECODER_INPUT_CHARS = 100_000

# The classic "ASCII smuggling" range: US-ASCII code points mapped into the Unicode Tags block
# (U+E0000..U+E007F), which many renderers hide but some models still read as instructions.
_ASCII_TAG_OFFSET = 0xE0000

DECODER_TRANSFORMS: tuple[str, ...] = ("base64", "rot13", "ascii_smuggling", "hex", "url")


@dataclass(frozen=True, slots=True)
class DecoderTransform:
    """One content-addressed encoding-bypass transform of an attack turn."""

    transform: str
    input_text: str
    output_text: str
    provenance_sha256: str


def _ascii_smuggle(text: str) -> str:
    for ch in text:
        if ord(ch) > 0x7F:
            raise ValueError("ascii_smuggling requires US-ASCII input")
    return "".join(chr(_ASCII_TAG_OFFSET + ord(ch)) for ch in text)


def _apply(transform: str, text: str) -> str:
    if transform == "base64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if transform == "rot13":
        return codecs.encode(text, "rot13")
    if transform == "ascii_smuggling":
        return _ascii_smuggle(text)
    if transform == "hex":
        return text.encode("utf-8").hex()
    if transform == "url":
        return quote(text, safe="")
    raise ValueError(f"unknown decoder transform {transform!r}")


def _provenance(transform: str, input_text: str, output_text: str) -> str:
    canonical = json.dumps(
        [transform, input_text, output_text], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def decode_transform(text: str, *, transform: str) -> DecoderTransform:
    """Apply one encoding transform to ``text``, fail-closed on unknown transform / oversize."""
    if transform not in DECODER_TRANSFORMS:
        raise ValueError(f"unknown decoder transform {transform!r}")
    if len(text) > MAX_DECODER_INPUT_CHARS:
        raise ValueError("decoder input is too large (exceeds the bound)")
    output_text = _apply(transform, text)
    return DecoderTransform(
        transform=transform,
        input_text=text,
        output_text=output_text,
        provenance_sha256=_provenance(transform, text, output_text),
    )


def decoder_variants(
    text: str, *, transforms: tuple[str, ...] = DECODER_TRANSFORMS
) -> tuple[DecoderTransform, ...]:
    """Return one content-addressed transform per requested encoding (encoding-bypass inputs)."""
    return tuple(decode_transform(text, transform=transform) for transform in transforms)


__all__ = [
    "DECODER_TRANSFORMS",
    "MAX_DECODER_INPUT_CHARS",
    "DecoderTransform",
    "decode_transform",
    "decoder_variants",
]
