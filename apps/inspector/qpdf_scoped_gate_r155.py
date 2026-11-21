"""R1.55 conservative per-object QPDF visual evidence gate.

The scanner controls encryption/AV/qpdf --check before this stage. Fetch
only identified objects and never use QPDF inline-stream mode for a whole PDF.
A negative finding is NOT a claim of full document transcription fidelity.
"""
from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Callable

from qpdf_paint_triage_r154 import (
    _parse_qpdf_json, _OCR_PAGE_REF, _inspect_qpdf_parsed,
    MAX_PAGES, MAX_STREAMS_PER_PAGE, ReviewRequired,
)

MAX_SCOPED_QPDF_OBJECTS_PER_DOCUMENT = 256


def scoped_page_has_uncovered_paint(
    *,
    pages_json: str,
    page: int,
    count: int,
    run: Callable[[list[str], Path], str],
    source: Path,
    directory: Path,
    cache: dict[tuple[str, bool], dict],
    calls: list[int],
) -> bool:
    """Only read identified page/font/stream objects in the QPDF v2 graph.

    Each subprocess has the host's existing 30s timeout, 2 MiB output cap and
    a 1 MiB QPDF JSON parser cap. 'True' requires review; 'False' only denotes
    the absence of this known subset of PDF painting operators.
    """
    if (not isinstance(cache, dict) or type(calls) is not list
            or len(calls) != 1 or type(calls[0]) is not int
            or not 0 <= calls[0] <= MAX_SCOPED_QPDF_OBJECTS_PER_DOCUMENT
            or not isinstance(source, Path) or not isinstance(directory, Path)):
        raise ReviewRequired("QPDF visual verification budget unavailable")
    catalog = _parse_qpdf_json(pages_json)
    pages = catalog.get("pages")
    if not isinstance(pages, list) or len(pages) != count:
        raise ReviewRequired("Untrusted QPDF page list")
    if type(page) is not int or not 1 <= page <= count <= MAX_PAGES:
        raise ReviewRequired("QPDF page identity outside budget")
    selected = pages[page - 1]
    if (not isinstance(selected, dict)
            or selected.get("pageposfrom1") != Decimal(page)
            or not isinstance(selected.get("object"), str)
            or not _OCR_PAGE_REF.fullmatch(selected["object"])):
        raise ReviewRequired("Unsupported QPDF selected page")
    ref = selected["object"]
    refs = selected.get("contents")
    if (not isinstance(refs, list) or not 1 <= len(refs) <= MAX_STREAMS_PER_PAGE
            or any(not isinstance(item, str) or not _OCR_PAGE_REF.fullmatch(item)
                   for item in refs)
            or len(set(refs)) != len(refs)):
        raise ReviewRequired("Unverified QPDF content stream inventory")

    def fetch(objref: str, *, decoded: bool = False) -> dict:
        if not isinstance(objref, str) or not _OCR_PAGE_REF.fullmatch(objref):
            raise ReviewRequired("Invalid QPDF object reference")
        key = (objref, decoded)
        # Font/page metadata is cached; base64-encoded decoded streams are
        # ephemeral and NEVER cached across 100-page documents.
        if not decoded and key in cache:
            return cache[key]
        if calls[0] >= MAX_SCOPED_QPDF_OBJECTS_PER_DOCUMENT:
            raise ReviewRequired("QPDF per-document visual query budget reached")
        calls[0] += 1
        number, generation = objref.split(" ")[:2]
        args = [
            "qpdf", "--json", "--json-key=qpdf",
            f"--json-object={number},{generation}",
        ]
        if decoded:
            args.extend(["--json-stream-data=inline", "--decode-level=all"])
        raw = run([*args, str(source)], directory)
        info = _parse_qpdf_json(raw)
        objects = info.get("qpdf")
        object_key = "obj:" + objref
        if (not isinstance(objects, list) or len(objects) != 2
                or not isinstance(objects[0], dict)
                or objects[0].get("jsonversion") != Decimal(2)
                or not isinstance(objects[1], dict)
                or set(objects[1]) != {object_key}
                or not isinstance(objects[1][object_key], dict)):
            raise ReviewRequired("QPDF selected object identity mismatch")
        result = objects[1][object_key]
        if not decoded:
            cache[key] = result
        return result

    page_obj = fetch(ref)
    if not isinstance(page_obj.get("value"), dict):
        raise ReviewRequired("QPDF page dictionary missing")
    values = page_obj["value"]
    if values.get("/Type") != "/Page":
        raise ReviewRequired("QPDF page dictionary type unsupported")
    page_contents = values.get("/Contents")
    if (page_contents != refs
            and not (len(refs) == 1 and page_contents == refs[0])):
        raise ReviewRequired("QPDF page contents do not match ordered inventory")
    resources = values.get("/Resources")
    if not isinstance(resources, dict):
        raise ReviewRequired("Unresolved or inherited QPDF visual resources")
    # This visual evidence may be in appearance streams or resources and
    # cannot be certified by a content stream text operator scan alone.
    if ("/Annots" in values
            or any(resource in resources for resource in
                   ("/Pattern", "/Shading", "/XObject", "/ExtGState"))):
        return True
    fonts = resources.get("/Font")
    if not isinstance(fonts, dict) or not fonts or len(fonts) > 32:
        raise ReviewRequired("QPDF font inventory unavailable")
    for font_ref in fonts.values():
        if not isinstance(font_ref, str) or not _OCR_PAGE_REF.fullmatch(font_ref):
            raise ReviewRequired("Unresolved PDF font resource")
        fetch(font_ref)
    objects: dict[str, dict] = {"obj:" + ref: page_obj}
    for font_ref in fonts.values():
        objects["obj:" + font_ref] = fetch(font_ref)
    for stream_ref in refs:
        objects["obj:" + stream_ref] = fetch(stream_ref, decoded=True)
    # Values remain Decimal as parsed by the strict QPDF JSON parser; no
    # approximate numeric re-serialization or raw-PDF regex inspection.
    report = {
        "version": Decimal(2),
        "pages": pages,
        "qpdf": [{"jsonversion": Decimal(2)}, objects],
    }
    return _inspect_qpdf_parsed(report, page=page, count=count)
