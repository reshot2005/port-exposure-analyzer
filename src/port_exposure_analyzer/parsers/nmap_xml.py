"""Nmap XML parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from secintel_core.security import bounded_read_file

from port_exposure_analyzer.models import Host, Inventory, Service

MAX_XML_BYTES = 50 * 1024 * 1024


def parse_nmap_xml(path: Path | str, *, max_bytes: int = MAX_XML_BYTES) -> Inventory:
    resolved = Path(path)
    content = bounded_read_file(resolved, max_bytes=max_bytes)
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError(f"expected nmaprun root, got {root.tag!r}")

    inventory = Inventory(scan_sources=[str(resolved)])
    for host_el in root.findall("host"):
        host = _parse_host(host_el)
        if host:
            inventory.hosts.append(host)
    return inventory


def _parse_host(host_el: ET.Element) -> Host | None:
    status_el = host_el.find("status")
    if status_el is not None and status_el.get("state") == "down":
        return None
    address = ""
    addr_type = "ipv4"
    for addr_el in host_el.findall("address"):
        at = addr_el.get("addrtype", "")
        if at in {"ipv4", "ipv6"}:
            address = addr_el.get("addr", "")
            addr_type = at
            break
    if not address:
        return None

    hostname = ""
    hn_el = host_el.find("hostnames/hostname")
    if hn_el is not None:
        hostname = hn_el.get("name", "")

    os_name = ""
    osmatch = host_el.find("os/osmatch")
    if osmatch is not None:
        os_name = osmatch.get("name", "")

    services: list[Service] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            svc = _parse_port(port_el)
            if svc:
                services.append(svc)

    return Host(address=address, address_type=addr_type, hostname=hostname, os_name=os_name, services=services)


def _parse_port(port_el: ET.Element) -> Service | None:
    port_id = port_el.get("portid")
    if not port_id:
        return None
    state_el = port_el.find("state")
    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
    svc_el = port_el.find("service")
    name = product = version = banner = ""
    if svc_el is not None:
        name = svc_el.get("name", "")
        product = svc_el.get("product", "")
        version = svc_el.get("version", "")
        banner = svc_el.get("banner", "") or svc_el.get("extrainfo", "")
    return Service(
        port=int(port_id), protocol=port_el.get("protocol", "tcp"),
        state=state, name=name, product=product, version=version, banner=banner,
    )
