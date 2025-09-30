#!/usr/bin/env python3
import os
import sys

EXTS = {'.cpp', '.h', '.asm'}

def strip_c_style_comments(src: str) -> str:
    out = []
    i = 0
    n = len(src)
    in_block = False
    in_line = False
    in_double = False
    in_single = False
    escape = False
    while i < n:
        ch = src[i]
        nxt = src[i+1] if i+1 < n else ''
        if in_block:
            if ch == '*' and nxt == '/':
                in_block = False
                i += 2
                continue
            else:
                i += 1
                continue
        if in_line:
            if ch == '\n':
                in_line = False
                out.append(ch)
            i += 1
            continue
        if not in_double and not in_single:
            if ch == '/' and nxt == '*':
                in_block = True
                i += 2
                continue
            if ch == '/' and nxt == '/':
                in_line = True
                i += 2
                continue
        # handle string/char quoting and escapes
        if ch == '"' and not in_single:
            if not escape:
                in_double = not in_double
        elif ch == "'" and not in_double:
            if not escape:
                in_single = not in_single
        if ch == '\\' and (in_double or in_single):
            escape = not escape
        else:
            escape = False
        out.append(ch)
        i += 1
    return ''.join(out)

def strip_asm_comments(src: str) -> str:
    out_lines = []
    in_double = False
    in_single = False
    for line in src.splitlines(True):
        res = []
        escape = False
        for i,ch in enumerate(line):
            if ch == '"' and not in_single:
                if not escape:
                    in_double = not in_double
            elif ch == "'" and not in_double:
                if not escape:
                    in_single = not in_single
            if (not in_double and not in_single) and (ch == ';' or ch == '#'):
                # drop remainder of line
                break
            res.append(ch)
            if ch == '\\':
                escape = not escape
            else:
                escape = False
        out_lines.append(''.join(res))
        # reset string state per line for typical asm; if you want to preserve multi-line strings, remove the next two lines
        in_double = False
        in_single = False
    return ''.join(out_lines)

def strip_comments_by_ext(path, text):
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.cpp', '.h'):
        # first remove C-style comments preserving strings
        return strip_c_style_comments(text)
    elif ext == '.asm':
        # remove common asm line comments ; and #
        # also remove C-style block comments if present
        t = strip_c_style_comments(text)
        return strip_asm_comments(t)
    else:
        return text

total = 0
per_file = []

for root, dirs, files in os.walk('.'):
    for name in files:
        ext = os.path.splitext(name)[1].lower()
        if ext in EXTS:
            full = os.path.join(root, name)
            try:
                with open(full, 'r', encoding='utf-8', errors='replace') as f:
                    src = f.read()
            except Exception as e:
                print(f"Could not read {full}: {e}", file=sys.stderr)
                continue
            cleaned = strip_comments_by_ext(full, src)
            # count non-empty lines after stripping comments and trimming whitespace
            count = sum(1 for line in cleaned.splitlines() if line.strip() != '')
            per_file.append((full, count))
            total += count

# print per-file and total
for fn, c in per_file:
    print(f"{fn}: {c}")
print(f"\nTotal (non-empty, comments removed): {total}")
