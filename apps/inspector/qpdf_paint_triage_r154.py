"""R1.54 research-only conservative PDF content-operator triage.

QPDF resolves streams, compression, object references and JSON identities.
This module ONLY detects obvious extra visual painting in decoded page streams.
A pass is NOT proof of complete visual coverage, safe fonts or clean PDF.
NEVER use this prototype as a production release decision.
"""
from __future__ import annotations

import base64
import binascii
from decimal import Decimal
import re

from inspector import ReviewRequired, _parse_qpdf_json, _OCR_PAGE_REF, MAX_PAGES

MAX_STREAM_BYTES = 128 * 1024
MAX_STREAMS_PER_PAGE = 16
MAX_TOTAL_CONTENT_BYTES = 256 * 1024
MAX_TOKENS = 50_000
NUMBER = re.compile(rb"[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))\Z")
ATOM = frozenset((b"true", b"false", b"null"))
WHITESPACE = b"\x00\x09\x0a\x0c\x0d\x20"
DELIMITERS = b"()<>[]{}/%"
# Only text and nonpainting graphics state are admitted in a RESEARCH sample.
# Other operators (paths, images, shadings, inline images, forms, patterns,
# marked content, transparency via gs, compatibility BX/EX...) need review.
NONPAINTING = frozenset((
    b"BT", b"ET", b"Tc", b"Tw", b"Tz", b"TL", b"Tf", b"Tr",
    b"Ts", b"Td", b"TD", b"Tm", b"T*", b"Tj", b"TJ", b"'", b'"',
    b"q", b"Q", b"cm", b"w", b"J", b"j", b"M", b"d",
    b"ri", b"i", b"rg", b"RG", b"g", b"G", b"k", b"K",
    b"cs", b"CS", b"sc", b"SC",
))


def _lex(data: bytes) -> list[bytes | None]:
    """Tokenize bounded decoded PDF content without parsing operators in strings.

    None denotes a non-operator operand (numbers, names, strings, arrays).
    The lexical grammar intentionally rejects unknown constructs rather than
    certifying opaque bytes as text-only.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_STREAM_BYTES:
        raise ReviewRequired("Decoded PDF content stream unavailable")
    pos = 0
    output: list[bytes | None] = []
    while pos < len(data):
        if len(output) > MAX_TOKENS:
            raise ReviewRequired("PDF content operator count exceeds limit")
        char = data[pos]
        if char in WHITESPACE:
            pos += 1
            continue
        if char == ord("%"):
            pos += 1
            while pos < len(data) and data[pos] not in (10, 13):
                pos += 1
            continue
        if char == ord("("):
            pos += 1
            depth = 1
            while pos < len(data) and depth:
                char = data[pos]
                pos += 1
                if char == ord("\\"):
                    if pos >= len(data):
                        raise ReviewRequired("Unterminated PDF string escape")
                    if data[pos] == 13:
                        pos += 1
                        if pos < len(data) and data[pos] == 10:
                            pos += 1
                    else:
                        pos += 1
                elif char == ord("("):
                    depth += 1
                    if depth > 16:
                        raise ReviewRequired("PDF string nesting limit exceeded")
                elif char == ord(")"):
                    depth -= 1
            if depth:
                raise ReviewRequired("Unterminated PDF content string")
            output.append(None)
            continue
        if char == ord("<"):
            if pos + 1 < len(data) and data[pos + 1] == ord("<"):
                raise ReviewRequired("Opaque PDF dictionary in content stream")
            pos += 1
            length = 0
            while pos < len(data) and data[pos] != ord(">"):
                if data[pos] not in WHITESPACE:
                    if data[pos] not in b"0123456789abcdefABCDEF":
                        raise ReviewRequired("Invalid PDF hex string")
                    length += 1
                pos += 1
            if pos >= len(data):
                raise ReviewRequired("Unterminated PDF hex string")
            pos += 1
            if length == 0:
                raise ReviewRequired("Empty PDF hex string")
            output.append(None)
            continue
        if char == ord("/"):
            pos += 1
            start = pos
            while pos < len(data) and data[pos] not in WHITESPACE + DELIMITERS:
                pos += 1
            name = data[start:pos]
            if not 1 <= len(name) <= 128 or any(c < 33 or c > 126 for c in name):
                raise ReviewRequired("Invalid PDF content resource name")
            output.append(None)
            continue
        if char in b"[]":
            output.append(bytes([char]))
            pos += 1
            continue
        if char in b")>}":
            raise ReviewRequired("Unexpected PDF content delimiter")
        start = pos
        while pos < len(data) and data[pos] not in WHITESPACE + DELIMITERS:
            pos += 1
        if pos == start:
            raise ReviewRequired("Unexpected PDF content token")
        value = data[start:pos]
        if len(value) > 64 or any(c < 33 or c > 126 for c in value):
            raise ReviewRequired("PDF content token invalid")
        output.append(None if NUMBER.fullmatch(value) or value in ATOM else value)
    return output


def has_uncovered_paint(data: bytes) -> bool:
    """True on evident path/graphic operations; exception on ambiguous syntax.

    Not a PDF conformance proof: only safely recognizes a small text-only
    subset. A false result MUST NOT be treated as G4 coverage certification.
    """
    nesting = 0
    text_object = False
    graphics_depth = 0
    seen_text = False
    for token in _lex(data):
        if token is None:
            continue
        if token == b"[":
            nesting += 1
            if nesting > 16:
                raise ReviewRequired("PDF text array nesting exceeded")
            continue
        if token == b"]":
            nesting -= 1
            if nesting < 0:
                raise ReviewRequired("Unbalanced PDF text array")
            continue
        if token not in NONPAINTING:
            return True
        if nesting:
            # No content operator may be executed inside a PDF array.
            raise ReviewRequired("Operator inside PDF text array")
        if token == b"BT":
            if text_object:
                raise ReviewRequired("Nested PDF text object")
            text_object = True
            seen_text = True
        elif token == b"ET":
            if not text_object:
                raise ReviewRequired("Unpaired PDF text end")
            text_object = False
        elif token == b"q":
            graphics_depth += 1
            if graphics_depth > 32:
                raise ReviewRequired("PDF graphics state stack exceeded")
        elif token == b"Q":
            graphics_depth -= 1
            if graphics_depth < 0:
                raise ReviewRequired("Unpaired PDF graphics state restore")
        elif token in (b"Tj", b"TJ", b"'", b'"') and not text_object:
            raise ReviewRequired("PDF text showing operator without text object")
    if nesting or text_object or graphics_depth or not seen_text:
        raise ReviewRequired("Incomplete or unmatched text-only PDF content")
    return False


def qpdf_page_has_uncovered_paint(raw: str, *, page: int, count: int) -> bool:
    """Consume a strict QPDF v2 JSON report of resolved decoded streams.

    Caller must have validated AV, encryption and structural qpdf --check.
    A false return has RESEARCH-ONLY significance, not release approval.
    """
    if type(page) is not int or type(count) is not int or not 1 <= page <= count <= MAX_PAGES:
        raise ReviewRequired("Invalid QPDF visual page identity")
    doc = _parse_qpdf_json(raw)
    pages = doc.get("pages")
    qpdf = doc.get("qpdf")
    if (not isinstance(pages, list) or len(pages) != count
            or not isinstance(qpdf, list) or len(qpdf) != 2
            or not isinstance(qpdf[0], dict)
            or qpdf[0].get("jsonversion") != Decimal(2)
            or not isinstance(qpdf[1], dict)):
        raise ReviewRequired("Incomplete QPDF decoded page stream inventory")
    selected = pages[page - 1]
    if (not isinstance(selected, dict)
            or selected.get("pageposfrom1") != Decimal(page)
            or not isinstance(selected.get("object"), str)
            or not _OCR_PAGE_REF.fullmatch(selected["object"])):
        raise ReviewRequired("QPDF visual page reference invalid")
    page_entry = qpdf[1].get("obj:" + selected["object"])
    if not isinstance(page_entry, dict) or not isinstance(page_entry.get("value"), dict):
        raise ReviewRequired("QPDF page dictionary unavailable")
    page_dict = page_entry["value"]
    if page_dict.get("/Type") != "/Page":
        raise ReviewRequired("QPDF page type invalid")
    # Even an empty annotation set is conservatively unsupported; annotation
    # appearance streams can draw additional visual facts outside /Contents.
    if "/Annots" in page_dict:
        return True
    resources = page_dict.get("/Resources")
    if not isinstance(resources, dict):
        raise ReviewRequired("QPDF page resources unresolved")
    if any(name in resources for name in ("/Pattern", "/Shading", "/XObject", "/ExtGState")):
        return True
    # A Type3 font's glyphs are *arbitrary PDF content streams* and can paint
    # vector marks even when the page stream itself contains only Tj operators.
    # The local test's ordinary Helvetica Type1 is the only known-safe subset;
    # unseen font formats are routed to review, not interpreted as coverage.
    fonts = resources.get("/Font")
    if not isinstance(fonts, dict) or not fonts or len(fonts) > 32:
        raise ReviewRequired("PDF font resources cannot be resolved")
    for resource_name, font_ref in fonts.items():
        if (not isinstance(resource_name, str)
                or not resource_name.startswith("/") or len(resource_name) > 130
                or not isinstance(font_ref, str)
                or not _OCR_PAGE_REF.fullmatch(font_ref)):
            raise ReviewRequired("Unsupported PDF font resource reference")
        font_obj = qpdf[1].get("obj:" + font_ref)
        if (not isinstance(font_obj, dict)
                or not isinstance(font_obj.get("value"), dict)):
            raise ReviewRequired("PDF font dictionary unavailable")
        font_dict = font_obj["value"]
        if font_dict.get("/Type") != "/Font":
            raise ReviewRequired("PDF font resource type unavailable")
        if font_dict.get("/Subtype") not in ("/Type1", "/TrueType"):
            return True

    refs = selected.get("contents")
    if (not isinstance(refs, list) or not 1 <= len(refs) <= MAX_STREAMS_PER_PAGE
            or any(not isinstance(ref, str) or not _OCR_PAGE_REF.fullmatch(ref)
                   for ref in refs)
            or len(set(refs)) != len(refs)):
        raise ReviewRequired("QPDF content stream count invalid")
    size = 0
    painted = False
    for ref in refs:
        if not isinstance(ref, str) or not _OCR_PAGE_REF.fullmatch(ref):
            raise ReviewRequired("QPDF content stream reference invalid")
        obj = qpdf[1].get("obj:" + ref)
        if not isinstance(obj, dict) or set(obj) != {"stream"}:
            raise ReviewRequired("QPDF referenced content stream absent")
        stream = obj["stream"]
        if (not isinstance(stream, dict)
                or not isinstance(stream.get("dict"), dict)
                or not isinstance(stream.get("data"), str)):
            raise ReviewRequired("QPDF decoded PDF stream missing")
        # --decode-level=all was requested: an unresolved Filter is never
        # interpreted as PDF operator tokens.
        if stream["dict"].get("/Filter") is not None:
            raise ReviewRequired("PDF stream filter not fully decoded")
        try:
            decoded = base64.b64decode(stream["data"], validate=True)
        except (ValueError, binascii.Error) as error:
            raise ReviewRequired("PDF content stream base64 unavailable") from error
        size += len(decoded)
        if size > MAX_TOTAL_CONTENT_BYTES:
            raise ReviewRequired("Decoded PDF page content exceeds budget")
        painted = has_uncovered_paint(decoded) or painted
    return painted
