"""Build a minimal but valid .xlsx, so XLSX loading can be tested without openpyxl.

Writes the same parts Excel does: shared strings, a styles table with a date
number format, and a sheet with sparse cells. That combination is what the
reader has to cope with in real workbooks.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Sequence

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

# cellXfs index 1 uses numFmtId 14 (a built-in date format).
STYLES = """<?xml version="1.0" encoding="UTF-8"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="1"><numFmt numFmtId="200" formatCode="yyyy\\-mm\\-dd"/></numFmts>
<cellXfs count="3">
<xf numFmtId="0"/>
<xf numFmtId="14" applyNumberFormat="1"/>
<xf numFmtId="200" applyNumberFormat="1"/>
</cellXfs>
</styleSheet>"""


def _letter(index: int) -> str:
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def write_xlsx(path: Path, sheets: dict[str, Sequence[Sequence[Any]]],
               *, date_columns: set[int] | None = None,
               skip_cells: set[tuple[int, int]] | None = None) -> Path:
    """Write `sheets` to `path`.

    A value given as ("date", serial) is written as an Excel date serial with a
    date style, which is how real spreadsheets store dates.
    `skip_cells` omits (row, column) entirely, producing the sparse cells that
    make cell references necessary.
    """

    skip = skip_cells or set()
    strings: list[str] = []
    index_of: dict[str, int] = {}

    def shared(value: str) -> int:
        if value not in index_of:
            index_of[value] = len(strings)
            strings.append(value)
        return index_of[value]

    sheet_parts: dict[str, str] = {}
    for number, (title, rows) in enumerate(sheets.items(), 1):
        body = []
        for row_index, row in enumerate(rows, 1):
            cells = []
            for column_index, value in enumerate(row):
                if (row_index, column_index) in skip or value is None:
                    continue
                reference = f"{_letter(column_index)}{row_index}"
                if isinstance(value, tuple) and value and value[0] == "date":
                    cells.append(f'<c r="{reference}" s="1"><v>{value[1]}</v></c>')
                elif isinstance(value, bool):
                    cells.append(f'<c r="{reference}" t="b"><v>{int(value)}</v></c>')
                elif isinstance(value, (int, float)):
                    cells.append(f'<c r="{reference}"><v>{value}</v></c>')
                else:
                    cells.append(f'<c r="{reference}" t="s"><v>{shared(str(value))}</v></c>')
            body.append(f'<row r="{row_index}">{"".join(cells)}</row>')
        sheet_parts[f"xl/worksheets/sheet{number}.xml"] = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetData>{"".join(body)}</sheetData></worksheet>'
        )

    titles = list(sheets)
    workbook_sheets = "".join(
        f'<sheet name="{title}" sheetId="{number}" '
        f'r:id="rId{number}"/>' for number, title in enumerate(titles, 1)
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{workbook_sheets}</sheets></workbook>"
    )
    relations = "".join(
        f'<Relationship Id="rId{number}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{number}.xml"/>' for number in range(1, len(titles) + 1)
    )
    extra = len(titles)
    relations += (
        f'<Relationship Id="rId{extra + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" '
        'Target="sharedStrings.xml"/>'
        f'<Relationship Id="rId{extra + 2}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{relations}</Relationships>"
    )
    shared_strings = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        f'count="{len(strings)}" uniqueCount="{len(strings)}">'
        + "".join(f"<si><t>{_escape(value)}</t></si>" for value in strings)
        + "</sst>"
    )

    sheet_overrides = "".join(
        f'<Override PartName="/{part}" ContentType="application/vnd.openxmlformats-'
        'officedocument.spreadsheetml.worksheet+xml"/>' for part in sheet_parts
    )
    content_types = CONTENT_TYPES.replace("</Types>", sheet_overrides + "</Types>")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("[Content_Types].xml", content_types)
        bundle.writestr("_rels/.rels", ROOT_RELS)
        bundle.writestr("xl/workbook.xml", workbook)
        bundle.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        bundle.writestr("xl/sharedStrings.xml", shared_strings)
        bundle.writestr("xl/styles.xml", STYLES)
        for part, text in sheet_parts.items():
            bundle.writestr(part, text)
    return path


def _escape(value: str) -> str:
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
