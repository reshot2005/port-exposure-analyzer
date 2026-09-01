"""Masscan list parser."""

from __future__ import annotations

import re
from pathlib import Path

from secintel_core.security import iter_bounded_lines

from port_exposure_analyzer.models import Host, Inventory, Service

_LINE = re.compile(
    r"^(?P<state>open|closed|filtered)\s+(?P<protocol>\w+)\s+"
    r"(?P<port>\d+)\s+(?P<address>[\d.a-fA-F:]+)\s+(?P<ts>\d+)$"
)


def parse_masscan_list(path: Path | str) -> Inventory:
    resolved = Path(path)
    hosts: dict[str, Host] = {}
    for line in iter_bounded_lines(resolved):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        addr = m.group("address")
        if addr not in hosts:
            hosts[addr] = Host(address=addr, address_type="ipv6" if ":" in addr else "ipv4")
        hosts[addr].services.append(Service(
            port=int(m.group("port")), protocol=m.group("protocol"), state=m.group("state"),
        ))
    return Inventory(hosts=list(hosts.values()), scan_sources=[str(resolved)])
