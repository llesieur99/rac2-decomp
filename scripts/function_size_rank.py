#!/usr/bin/env python3
"""Analyze and rank functions by size using progress/candidates.json data.

This script extracts function sizes from the decompilation progress data
and generates a ranked list that can be used to identify small, medium, and
large functions for targeted decompilation work.

The progress/candidates.json contains verified function information including:
- Symbol names and addresses
- Candidate SHA256 hashes (for matching verification)
- Size information
- Match status

Usage:
    python scripts/function_size_rank.py [OPTIONS]

Options:
    --format {json,table,csv,compact}  Output format (default: table)
    --limit N                  Show only top N functions
    --min-size N               Minimum function size (default: 0)
    --max-size N               Maximum function size (default: no limit)
    --category {small,medium,big,all}
                               Filter by category (default: all)
    --output PATH              Output file path
    --region {usa,eu}          Region to analyze (default: usa)

Categories:
    small:   0-100 bytes
    medium:  101-500 bytes
    big:     501+ bytes

Note: This script uses progress/candidates.json which contains verified
function data from the decompilation process.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
CANDIDATES_JSON = ROOT / "progress" / "candidates.json"


class Function(NamedTuple):
    name: str
    address: int
    size: int
    category: str
    symbol: str  # The actual symbol name from candidates


def parse_candidates_functions(region: str = "usa") -> list[Function]:
    """Extract function data from progress/candidates.json."""
    try:
        with open(CANDIDATES_JSON, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: candidates.json not found at {CANDIDATES_JSON}")
        print("Run the build system first to generate progress data.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing candidates.json: {e}")
        return []
    
    functions = []
    
    # Get the functions array from candidates
    func_list = data.get('functions', [])
    
    for func in func_list:
        symbol = func.get('symbol', '')
        if not symbol:
            continue
        
        address = func.get('address', 0)
        if isinstance(address, str):
            try:
                address = int(address, 16)
            except ValueError:
                continue
        else:
            address = int(address)
        
        # Get size - try different field names
        size = func.get('size', func.get('byteSize', func.get('length', 64)))
        if isinstance(size, str):
            try:
                if size.startswith('0x'):
                    size = int(size, 16)
                else:
                    size = int(size)
            except ValueError:
                size = 64
        else:
            size = int(size)
        
        # Determine category based on size
        if size <= 100:
            category = "small"
        elif size <= 500:
            category = "medium"
        else:
            category = "big"
        
        functions.append(Function(
            name=symbol,
            address=address,
            size=size,
            category=category,
            symbol=symbol
        ))
    
    return functions


def categorize_function(size: int) -> str:
    """Categorize a function by size."""
    if size <= 100:
        return "small"
    elif size <= 500:
        return "medium"
    else:
        return "big"


def rank_functions(functions: list[Function]) -> list[Function]:
    """Rank functions by size (largest first)."""
    return sorted(functions, key=lambda f: f.size, reverse=True)


def filter_functions(
    functions: list[Function],
    min_size: int = 0,
    max_size: int | None = None,
    category: str | None = None
) -> list[Function]:
    """Filter functions by size and/or category."""
    filtered = []
    for func in functions:
        if func.size < min_size:
            continue
        if max_size is not None and func.size > max_size:
            continue
        if category and func.category != category:
            continue
        filtered.append(func)
    return filtered


def format_output(
    functions: list[Function],
    format_type: str,
    limit: int | None = None
) -> str:
    """Format functions output in the specified format."""
    if limit:
        functions = functions[:limit]
    
    if format_type == "json":
        return json.dumps([
            {"name": f.name, "address": hex(f.address), "size": f.size, "category": f.category}
            for f in functions
        ], indent=2)
    
    elif format_type == "csv":
        lines = ["name,address,size,category"]
        for f in functions:
            lines.append(f"{f.name},{hex(f.address)},{f.size},{f.category}")
        return "\n".join(lines)
    
    elif format_type == "compact":
        # Simple format: func_xxxx size
        lines = []
        for f in functions:
            lines.append(f"{f.name} {f.size}")
        return "\n".join(lines)
    
    else:  # table
        if not functions:
            return "No functions found"
        
        lines = []
        lines.append(f"{'Name':<40} {'Address':<10} {'Size':>8} {'Category':<10}")
        lines.append("-" * 70)
        for f in functions:
            # Truncate long names
            name = f.name[:37] + "..." if len(f.name) > 40 else f.name
            lines.append(f"{name:<40} {hex(f.address):<10} {f.size:>8} {f.category:<10}")
        
        # Summary
        total = len(functions)
        small = sum(1 for f in functions if f.category == "small")
        medium = sum(1 for f in functions if f.category == "medium")
        big = sum(1 for f in functions if f.category == "big")
        
        lines.append("")
        lines.append(f"Total functions: {total}")
        lines.append(f"  Small (0-100):     {small}")
        lines.append(f"  Medium (101-500):  {medium}")
        lines.append(f"  Big (501+):        {big}")
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze and rank functions by size across the RAC2 codebase"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "table", "csv"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=None,
        help="Show only top N functions"
    )
    parser.add_argument(
        "--min-size", "-m",
        type=int,
        default=0,
        help="Minimum function size (default: 0)"
    )
    parser.add_argument(
        "--max-size", "-x",
        type=int,
        default=None,
        help="Maximum function size (default: no limit)"
    )
    parser.add_argument(
        "--category", "-c",
        choices=["small", "medium", "big", "all"],
        default="all",
        help="Filter by category (default: all)"
    )
    parser.add_argument(
        "--region", "-r",
        choices=["usa", "eu"],
        default="usa",
        help="Region to analyze (default: usa)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path"
    )
    
    args = parser.parse_args()
    
    # Parse functions from candidates.json
    print(f"Parsing functions from {CANDIDATES_JSON}...")
    functions = parse_candidates_functions(region=args.region)
    
    if not functions:
        print("Warning: No function symbols found.")
        print("Run the build system first to generate progress data.")
        return 1
    
    print(f"Found {len(functions)} functions")
    
    # Rank and filter
    ranked = rank_functions(functions)
    filtered = filter_functions(
        ranked,
        min_size=args.min_size,
        max_size=args.max_size,
        category=args.category
    )
    
    # Format and output
    output = format_output(filtered, args.format, args.limit)
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"Output written to {args.output}")
    else:
        print(output)
    
    return 0


if __name__ == "__main__":
    exit(main())
