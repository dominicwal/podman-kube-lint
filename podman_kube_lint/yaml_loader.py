"""YAML and Jinja parsing helpers."""

from __future__ import annotations

import re

import yaml

from .rules import PH

class LDict(dict):
    def __init__(self):
        super().__init__()
        self.line = 0
        self.klines: dict = {}


class LList(list):
    def __init__(self):
        super().__init__()
        self.line = 0
        self.lines: list[int] = []


class Loader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.dups: list[tuple] = []


def _construct_map(loader: Loader, node):
    loader.flatten_mapping(node)
    d = LDict()
    d.line = node.start_mark.line
    for kn, vn in node.value:
        k = loader.construct_object(kn, deep=True)
        try:
            hash(k)
        except TypeError:
            raise yaml.constructor.ConstructorError(None, None, "Key is not hashable", kn.start_mark)
        v = loader.construct_object(vn, deep=True)
        if k in d:
            loader.dups.append((k, kn.start_mark.line))
        d[k] = v
        d.klines[k] = kn.start_mark.line
    return d


def _construct_seq(loader: Loader, node):
    out = LList()
    out.line = node.start_mark.line
    for n in node.value:
        out.append(loader.construct_object(n, deep=True))
        out.lines.append(n.start_mark.line)
    return out


Loader.add_constructor("tag:yaml.org,2002:map", _construct_map)
Loader.add_constructor("tag:yaml.org,2002:seq", _construct_seq)


# ---------------------------------------------------------------------------
# Neutralize Jinja without rendering it; preserve line numbers
# ---------------------------------------------------------------------------
def neutralize_jinja(text: str) -> tuple[str, bool]:
    dynamic = False

    def blank(m):
        return "\n" * m.group(0).count("\n")

    text = re.sub(r"\{#.*?#\}", blank, text, flags=re.S)
    text = re.sub(r"\{%.*?%\}", blank, text, flags=re.S)

    def standalone(m):
        nonlocal dynamic
        dynamic = True
        return blank(m)

    # A line containing only {{ ... }} (for example, {{ x | to_nice_yaml | indent(4) }}) is a dynamic block.
    text = re.sub(r"(?m)^[ \t]*\{\{.*?\}\}[ \t]*$", standalone, text, flags=re.S)
    text = re.sub(r"\{\{.*?\}\}", lambda m: PH + "\n" * m.group(0).count("\n"), text, flags=re.S)
    return text, dynamic


def split_docs(text: str) -> list[tuple[int, str]]:
    """Split multi-document YAML and return zero-based start lines and text."""
    docs, cur, start = [], [], 0
    for i, line in enumerate(text.split("\n")):
        if re.match(r"^---(\s|$)", line):
            docs.append((start, "\n".join(cur)))
            cur, start = [], i + 1
        elif re.match(r"^\.\.\.(\s|$)", line):
            continue
        else:
            cur.append(line)
    docs.append((start, "\n".join(cur)))
    return docs


def is_blank_doc(t: str) -> bool:
    return all(not l.strip() or l.strip().startswith("#") or l.startswith("%") for l in t.split("\n"))
