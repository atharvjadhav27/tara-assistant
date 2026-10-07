import io

from app import config
from app.knowledge import _windows, chunk_document, clean_text, est_tokens, parse_document


def test_clean_removes_duplicate_paragraphs_and_normalises_names():
    t = clean_text("The telematics unit stores keys in the hardware security module.\n\nThe telematics unit stores keys in the hardware security module.")
    assert t.count("TCU") == 1 and "HSM" in t


def test_windows_respect_token_cap_and_overlap():
    text = " ".join(f"w{i}" for i in range(3000))
    parts = _windows(text, 800, 0.12)
    assert len(parts) > 1
    assert all(est_tokens(p) <= 810 for p in parts)
    a, b = parts[0].split(), parts[1].split()
    overlap = len(set(a) & set(b))
    assert 0.08 * len(a) <= overlap <= 0.2 * len(a)


def test_pdf_headers_and_footers_removed():
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    for i in range(4):
        c.drawString(50, 800, "CONFIDENTIAL HEADER")
        c.drawString(50, 700, f"Interface: OTA page {i} unique body text number {i}.")
        c.showPage()
    c.save()
    d = parse_document("arch.pdf", buf.getvalue())
    assert "CONFIDENTIAL HEADER" not in d.text and "unique body text" in d.text


def test_threat_library_one_chunk_per_entry_with_citation():
    raw = (config.SAMPLE_DIR / "threat_library_v1.2.json").read_bytes()
    d = parse_document("threat_library_v1.2.json", raw)
    chunks = chunk_document(d, "__global__", "x")
    assert len(chunks) == len(d.records) == 21
    c = next(c for c in chunks if c.meta["record_id"] == "TL-OTA-03")
    assert c.meta["citation"] == "TL-OTA-03 | Threat Library v1.2, p.14"
    assert c.meta["interface"] == "OTA" and c.meta["asset_tag"] == "ota_package"


def test_architecture_sections_get_interface_metadata():
    d = parse_document("arch.md", (config.SAMPLE_DIR / "architecture_TCU-Gen2.md").read_bytes())
    ifaces = {c.meta["interface"] for c in chunk_document(d, "P", "x")}
    assert {"CAN", "ETH", "DIAG", "OTA", "BACKEND", "HW"} <= ifaces


def test_unsupported_type_rejected():
    import pytest

    with pytest.raises(ValueError):
        parse_document("x.exe", b"MZ")
