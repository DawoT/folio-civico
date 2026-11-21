"""Synthetic QPDF v2 reports for scoped R1.55 PDF visual admission tests.

No engine subprocess, PDF bytes, institutional data or external files. Actual
QPDF/Poppler/AV behavior is independently verified in the real-engine smoke.
"""
from __future__ import annotations

import base64
import json


def visual_qpdf_report(
    argv: list[str], *, count: int = 2, user_unit: object | None = None,
    text: str = "Synthetic native page text",
) -> str:
    """Mirror selected QPDF v2 object identities and decoded stream envelope.

    For each page i: page object 3+i, content stream 103+i; shared Type1 font
    object 900. The runner never fabricates a whole-document inline JSON
    report (only --json-object per referenced stream).
    """
    if argv[:2] != ["qpdf", "--json"]:
        raise AssertionError("Not a QPDF JSON query")
    if "--json-key=pages" in argv:
        return json.dumps({
            "version": 2,
            "pages": [
                {
                    "object": f"{index + 3} 0 R",
                    "pageposfrom1": index + 1,
                    "contents": [f"{index + 103} 0 R"],
                    "images": [],
                }
                for index in range(count)
            ],
        })
    if "--json-key=qpdf" not in argv:
        raise AssertionError("Unexpected QPDF JSON contract")
    selector = next(
        (item for item in argv if item.startswith("--json-object=")), None
    )
    if selector is None:
        raise AssertionError("A scoped QPDF object is required")
    number, generation = selector.split("=", 1)[1].split(",")
    if generation != "0" or not number.isdecimal():
        raise AssertionError("Unexpected QPDF object generation")
    object_id = int(number)
    if 3 <= object_id < 3 + count:
        page = object_id - 3
        value = {
            "/Type": "/Page",
            "/Contents": f"{103 + page} 0 R",
            "/Resources": {"/Font": {"/F1": "900 0 R"}},
            "/MediaBox": [0, 0, 612, 792],
        }
        if user_unit is not None:
            value["/UserUnit"] = user_unit
        body = {"value": value}
    elif object_id == 900:
        body = {"value": {
            "/Type": "/Font", "/Subtype": "/Type1", "/BaseFont": "/Helvetica",
        }}
    elif 103 <= object_id < 103 + count:
        if ("--json-stream-data=inline" not in argv
                or "--decode-level=all" not in argv):
            raise AssertionError("Decoded stream flags required")
        stream = (
            f"BT /F1 12 Tf 20 300 Td ({text}) Tj ET\n"
        ).encode("ascii")
        body = {"stream": {
            "dict": {},
            "data": base64.b64encode(stream).decode("ascii"),
        }}
    else:
        raise AssertionError("QPDF queried an unrelated object")
    return json.dumps({
        "version": 2,
        "qpdf": [
            {"jsonversion": 2}, {f"obj:{object_id} 0 R": body},
        ],
    })
