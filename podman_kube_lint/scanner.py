"""File discovery and YAML analysis."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .findings import Ctx
from .rules import DOC_VERSION, FILE_RE, J2_RE, KIND_GUESS, SUPPORTED_KINDS, YAML_J2_RE
from .validation import check_doc, kl, tn
from .yaml_loader import LDict, Loader, is_blank_doc, neutralize_jinja, split_docs

@dataclass
class Chunk:
    offset: int
    data: object = None
    error: Exception | None = None
    guess: str = ""
    dups: list | None = None


@dataclass
class ParsedFile:
    rel: str
    raw: list
    is_j2: bool
    dynamic: bool
    chunks: list
    podman: bool


def parse_file(path: Path, rel: str, all_kinds: bool) -> ParsedFile | None:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    except OSError:
        return None
    raw = text.split("\n")
    is_j2 = bool(J2_RE.search(path.name))
    dynamic = False
    if is_j2:
        text, dynamic = neutralize_jinja(text)
    chunks = []
    for off, t in split_docs(text):
        if is_blank_doc(t):
            continue
        ch = Chunk(offset=off, guess=(KIND_GUESS.search(t).group(1) if KIND_GUESS.search(t) else ""))
        ld = Loader(t)
        try:
            ch.data = ld.get_single_data()
            ch.dups = ld.dups
        except yaml.YAMLError as e:
            ch.error = e
        finally:
            ld.dispose()
        chunks.append(ch)
    podman = False
    for ch in chunks:
        if isinstance(ch.data, dict):
            k = ch.data.get("kind")
            if k in SUPPORTED_KINDS or (all_kinds and k and ch.data.get("apiVersion")):
                podman = True
        elif ch.error and ch.guess in SUPPORTED_KINDS:
            podman = True
    if not podman:
        return None
    return ParsedFile(rel, raw, is_j2, dynamic, chunks, podman)


def analyze(pf: ParsedFile, index: set, out: list, all_kinds: bool):
    seen_docs: dict = {}
    for ch in pf.chunks:
        c = Ctx(pf.rel, ch.offset, pf.raw, pf.dynamic, pf.is_j2, ch.guess, index, out)
        if ch.error is not None:
            mark = getattr(ch.error, "problem_mark", None)
            prob = getattr(ch.error, "problem", None) or str(ch.error)
            ctx = getattr(ch.error, "context", None)
            c.err(mark.line if mark else 0, "PK-SYNTAX", f"YAML syntax error: {prob}" + (f" ({ctx})" if ctx else ""))
            continue
        d = ch.data
        if not isinstance(d, LDict):
            c.err(0, "PK-NO-MAPPING", f"Document is not a mapping; got {tn(d)} (check indentation)")
            continue
        kind = d.get("kind")
        c.kind = kind if isinstance(kind, str) else ""
        md = d.get("metadata")
        if isinstance(md, LDict) and isinstance(md.get("name"), str):
            c.name = md["name"]
        for k, line in (ch.dups or []):
            (c.warn if pf.is_j2 else c.err)(line, "PK-DUP-KEY",
                                             f"Duplicate key {k!r}" + (" (may be from an if/else branch in a Jinja template)" if pf.is_j2 else ""))
        if kind is None:
            c.err(d.line, "PK-NO-KIND", "Document has no 'kind'; podman kube play will reject it")
            continue
        if not isinstance(kind, str) or kind not in SUPPORTED_KINDS:
            c.warn(kl(d, "kind"), "PK-KIND-UNSUPPORTED",
                   f"kind {kind!r} is not supported by podman kube play {DOC_VERSION} "
                   f"(supported kinds: {', '.join(SUPPORTED_KINDS)}) – this file would not start")
            continue
        key = (kind, c.name)
        if c.name and key in seen_docs:
            c.err(d.line, "PK-DUPLICATE", f"{kind} {c.name!r} is defined more than once in this file (first definition: line {seen_docs[key]})")
        else:
            seen_docs[key] = d.line + ch.offset + 1
        check_doc(c, d, kind)


def iter_files(roots, excludes, skip_dirs):
    for root in roots:
        root = Path(root)
        if root.is_file():
            yield root, root.parent
            continue
        for dp, dns, fns in os.walk(root, followlinks=False):
            dns[:] = sorted(d for d in dns if d not in skip_dirs)
            for fn in sorted(fns):
                if not FILE_RE.search(fn):
                    continue
                p = Path(dp) / fn
                rel = p.relative_to(root).as_posix()
                if any(fnmatch.fnmatch(rel, ex) or fnmatch.fnmatch(fn, ex) or ex in rel.split("/") for ex in excludes):
                    continue
                if J2_RE.search(fn) and not YAML_J2_RE.search(fn) and not re.search(r"\.ya?ml", fn, re.I):
                    continue  # For example, nginx.conf.j2
                yield p, root
