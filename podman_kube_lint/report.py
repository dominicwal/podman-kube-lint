"""Text report rendering."""

from .rules import DOC_URL, DOC_VERSION, SEV_RANK

class Col:
    def __init__(self, on):
        self.on = on

    def __call__(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.on else s


def render_text(findings, stats, col, min_sev, snippet):
    lines = []
    sev_col = {"ERROR": "31;1", "WARNING": "33;1", "INFO": "36"}
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[min_sev]]
    cur = None
    for f in sorted(shown, key=lambda f: (f.file, f.line, -SEV_RANK[f.severity])):
        if f.file != cur:
            cur = f.file
            lines += ["", col("1", cur)]
        who = f" [{f.kind}/{f.name}]" if f.kind and f.name else (f" [{f.kind}]" if f.kind else "")
        lines.append(f"  {col('2', f'L{f.line:<5}')} {col(sev_col[f.severity], f'{f.severity:<7}')} "
                     f"{col('35', f.rule)}{col('2', who)}")
        lines.append(f"         {f.message}")
        if snippet and f.snippet:
            lines.append(col("2", f"         > {f.snippet}"))
    cnt = {s: sum(1 for f in findings if f.severity == s) for s in SEV_RANK}
    bad_files = len({f.file for f in findings if f.severity in ("ERROR", "WARNING")})
    lines += ["", "─" * 60,
              f"Scanned: {stats['yaml']} YAML file(s) · Podman manifests: {stats['podman']} file(s) · "
              f"skipped (no Podman kind): {stats['skipped']}",
              f"Findings: {col(sev_col['ERROR'], str(cnt['ERROR']) + ' errors')}, "
              f"{col(sev_col['WARNING'], str(cnt['WARNING']) + ' warnings')}, "
              f"{cnt['INFO']} info  →  {bad_files} file(s) affected",
              f"Reference: Podman {DOC_VERSION} – {DOC_URL}"]
    if cnt["ERROR"] == 0 and cnt["WARNING"] == 0:
        lines.insert(-1, col("32;1", "No issues found ✔"))
    return "\n".join(lines)
