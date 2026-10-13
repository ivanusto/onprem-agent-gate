"""A small reader for the front matter the change records use.

The block between the first two `---` lines is `key: value` pairs; a key
followed by nothing and then `  - item` lines is a list. Nothing else
(no nesting, no quoting rules, no YAML library). Values are strings; the
caller converts dates. Returns (meta dict, body text, line number where
the body starts).
"""
import re

KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(.*)$")
ITEM_RE = re.compile(r"^\s+-\s+(.*\S)\s*$")


class FrontMatterError(ValueError):
    pass


def parse(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise FrontMatterError("file must start with a '---' front matter line")
    meta = {}
    i = 1
    cur = None
    while i < len(lines):
        line = lines[i]
        if line.strip() == "---":
            return meta, "\n".join(lines[i + 1:]), i + 2
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = KEY_RE.match(line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key in meta:
                raise FrontMatterError(f"line {i + 1}: duplicate key {key}")
            meta[key] = val
            cur = key if val == "" else None
        else:
            it = ITEM_RE.match(line)
            if it and cur is not None:
                if meta[cur] == "":
                    meta[cur] = []
                if not isinstance(meta[cur], list):
                    raise FrontMatterError(f"line {i + 1}: list item under a scalar key {cur}")
                meta[cur].append(it.group(1))
            else:
                raise FrontMatterError(f"line {i + 1}: not 'key: value' or '  - item': {line!r}")
        i += 1
    raise FrontMatterError("front matter never closed with '---'")


def sections(body):
    """'## Heading' -> text until the next '## '. Keys are heading texts."""
    out, cur, buf = {}, None, []
    for line in body.splitlines():
        if line.startswith("## "):
            if cur is not None:
                out[cur] = "\n".join(buf).strip()
            cur, buf = line[3:].strip(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf).strip()
    return out
