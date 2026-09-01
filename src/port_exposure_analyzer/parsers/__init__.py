"""Scan format dispatch."""

from __future__ import annotations

from pathlib import Path

from port_exposure_analyzer.models import Inventory
from port_exposure_analyzer.parsers.masscan import parse_masscan_list
from port_exposure_analyzer.parsers.nmap_xml import parse_nmap_xml


def parse_scan_file(path: Path | str, *, max_bytes: int = 50 * 1024 * 1024) -> Inventory:
    resolved = Path(path)
    if not resolved.is_file():
        raise ValueError(f"scan file not found: {resolved}")
    suffix = resolved.suffix.lower()
    if suffix == ".xml":
        return parse_nmap_xml(resolved, max_bytes=max_bytes)
    peek = resolved.read_text(encoding="utf-8", errors="replace")[:200]
    if peek.lstrip().startswith(("<?xml", "<nmaprun")):
        return parse_nmap_xml(resolved, max_bytes=max_bytes)
    return parse_masscan_list(resolved)
