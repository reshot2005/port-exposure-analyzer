#!/usr/bin/env python3
"""Bootstrap a new tool from the module-template.

Substitutes port-exposure-analyzer, Port Exposure Analyzer, and __ORG_NAME__ placeholders.

Usage:
    python scripts/new_tool.py --slug my-tool --name "My Tool" --output ../my-tool
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules"}
SKIP_FILES: set[str] = set()

REPLACEMENTS_TEMPLATE = [
    ("port_exposure_analyzer", "{slug_underscore}"),
    ("port-exposure-analyzer", "{slug_kebab}"),
    ("Port Exposure Analyzer", "{name}"),
    ("port-exposure-analyzer", "{slug_kebab}"),
    ("Port Exposure Analyzer", "{name}"),
    ("__ORG_NAME__", "{org}"),
]


def slug_to_underscore(slug: str) -> str:
    return slug.replace("-", "_")


def slug_to_package_name(slug: str) -> str:
    return slug.replace("-", "_")


def copy_and_substitute(
    src: Path,
    dst: Path,
    *,
    slug_kebab: str,
    slug_underscore: str,
    name: str,
    org: str,
) -> None:
    """Copy template directory, substituting placeholders."""
    replacements = [
        ("port_exposure_analyzer", slug_underscore),
        ("port-exposure-analyzer", slug_kebab),
        ("Port Exposure Analyzer", name),
        ("port-exposure-analyzer", slug_kebab),
        ("Port Exposure Analyzer", name),
        ("__ORG_NAME__", org),
    ]

    for item in src.rglob("*"):
        rel = item.relative_to(src)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if item.name in SKIP_FILES:
            continue

        dest_rel = str(rel)
        for old, new in replacements:
            dest_rel = dest_rel.replace(old, new)
        dest = dst / dest_rel

        if item.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                content = item.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                shutil.copy2(item, dest)
                continue
            for old, new in replacements:
                content = content.replace(old, new)
            dest.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap a new tool from module-template")
    parser.add_argument("--slug", required=True, help="Tool slug in kebab-case (e.g. dns-traffic-analyzer)")
    parser.add_argument("--name", required=True, help='Human-readable tool name (e.g. "DNS Traffic Analyzer")')
    parser.add_argument("--org", default="__ORG_NAME__", help="Organization name placeholder")
    parser.add_argument("--output", required=True, type=Path, help="Output directory for the new tool")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output directory")
    args = parser.parse_args()

    if not re.match(r"^[a-z][a-z0-9-]*[a-z0-9]$", args.slug) and not re.match(r"^[a-z]$", args.slug):
        print(f"Error: invalid slug '{args.slug}'. Use kebab-case.", file=sys.stderr)
        return 1

    template_dir = Path(__file__).resolve().parent.parent
    if args.output.exists():
        if not args.force:
            print(f"Error: {args.output} already exists. Use --force to overwrite.", file=sys.stderr)
            return 1
        shutil.rmtree(args.output)

    slug_underscore = slug_to_underscore(args.slug)
    copy_and_substitute(
        template_dir,
        args.output,
        slug_kebab=args.slug,
        slug_underscore=slug_underscore,
        name=args.name,
        org=args.org,
    )
    print(f"Created tool at {args.output.resolve()}")
    print(f"  Package: {slug_underscore}")
    print(f"  CLI entry: {args.slug}")
    print()
    print("Next steps:")
    print(f"  cd {args.output}")
    print("  py -3.12 -m venv .venv")
    print("  pip install -e ../secintel-core")
    print('  pip install -e ".[dev]"')
    print(f"  {args.slug} analyze sample_data/example.txt --json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
