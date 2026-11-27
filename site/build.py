#!/usr/bin/env python3
"""Stage the repository's Markdown into site/src for mdBook.

Every tracked *.md (except the vendored Kamailio corpus) is copied to the
same path under site/src, so the ~1,400 relative links between them keep
working as written for GitHub. Images they reference are copied alongside.
Links to anything else in the repository (directories, source files,
configs) are pointed at GitHub. SUMMARY.md is generated, and every staged
page must appear in it: mdBook doesn't render pages missing from it.

Usage: python3 site/build.py && mdbook build site
"""
import os, re, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "site", "src")
REPO_URL = "https://github.com/RustedBytes/ferrosip"
ASSETS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")

# The guide's order; everything else is grouped below by where it lives.
USING = ["docs/running.md", "docs/config-toml.md", "docs/fsr.md", "docs/script.md", "docs/import.md", "docs/lint.md", "docs/sip.md", "docs/kamailio-compat.md"]
REFERENCE = ["docs/modules-overview.md", "docs/modules-reference.md", "docs/functions-reference.md", "docs/lints-reference.md", "docs/glossary.md"]
INTERNALS = ["docs/architecture.md", "docs/design-notes.md", "docs/sip-ua.md", "docs/sip-ua-rfc-matrix.md", "docs/testing.md", "docs/benchmarks.md", "bench/BASELINE.md", "tests/compat/README.md"]

LINK = re.compile(r"(!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\()(<[^>]*>|[^)\s]+)((?:\s+\"[^\"]*\")?\))")
HTML_ATTR = re.compile(r"""(\b(?:src|href)=")([^"]+)(")""")
REF_DEF = re.compile(r"^( {0,3}\[[^\]]+\]:\s+)(\S+)(.*)$", re.M)
FENCE = re.compile(r"^( {0,3})(```+|~~~+)")


def pages():
    out = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    return sorted(p for p in out if not p.startswith(("tests/compat/kamailio/", "site/")))


def title(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        for line in f:
            if line.startswith("# "):
                return line[2:].strip()
    return path


class Linker:
    def __init__(self, staged):
        self.staged = set(staged)
        self.assets = set()
        self.warnings = []

    def fix(self, page, url):
        """The link as the site needs it (unchanged when it already works)."""
        bare = url[1:-1] if url.startswith("<") and url.endswith(">") else url
        if not bare or bare.startswith("#") or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", bare) or bare.startswith("/"):
            return url
        path, _, frag = bare.partition("#")
        target = os.path.normpath(os.path.join(os.path.dirname(page), path))
        if target.startswith(".."):
            self.warnings.append(f"{page}: {url} leaves the repository")
            return url
        if target in self.staged:
            return url
        full = os.path.join(ROOT, target)
        if target.lower().endswith(ASSETS) and os.path.isfile(full):
            self.assets.add(target)
            return url
        if os.path.isdir(full):
            return f"{REPO_URL}/tree/main/{target}" + (f"#{frag}" if frag else "")
        if os.path.isfile(full):
            return f"{REPO_URL}/blob/main/{target}" + (f"#{frag}" if frag else "")
        self.warnings.append(f"{page}: {url} points at nothing")
        return url

    def rewrite_text(self, page, text):
        """Rewrite links in prose, leaving inline code spans alone. Code
        spans become placeholders first, so a link whose text is code
        ([`examples/toml/`](…)) still matches."""
        spans = []

        def hide(m):
            spans.append(m.group(0))
            return f"\x00{len(spans) - 1}\x00"

        text = re.sub(r"(`+)[^`]*?\1", hide, text)
        text = LINK.sub(lambda m: m.group(1) + self.fix(page, m.group(2)) + m.group(3), text)
        text = HTML_ATTR.sub(lambda m: m.group(1) + self.fix(page, m.group(2)) + m.group(3), text)
        return re.sub(r"\x00(\d+)\x00", lambda m: spans[int(m.group(1))], text)

    def rewrite(self, page, md):
        out, prose, fence = [], [], None
        for line in md.split("\n"):
            m = FENCE.match(line)
            if fence is None and m:
                out.append(self.rewrite_text(page, "\n".join(prose))) if prose else None
                prose, fence = [], m.group(2)
                out.append(line)
            elif fence is not None:
                out.append(line)
                if line.strip().startswith(fence[0] * len(fence)) and line.strip().strip(fence[0]) == "":
                    fence = None
            else:
                prose.append(line)
        if prose:
            out.append(self.rewrite_text(page, "\n".join(prose)))
        text = "\n".join(out)
        return REF_DEF.sub(lambda m: m.group(1) + self.fix(page, m.group(2)) + m.group(3), text)


def summary(all_pages):
    left = set(all_pages)
    lines = ["# Summary", ""]

    def item(path, depth=0):
        left.discard(path)
        lines.append(f"{'  ' * depth}- [{title(path)}]({path})")

    def part(name, paths):
        lines.extend(["", f"# {name}", ""])
        for p in paths:
            item(p)

    left.discard("README.md")
    lines.append(f"[{title('README.md')}](README.md)")
    part("Using ferrosip", USING)
    part("Reference", REFERENCE)
    part("Internals", INTERNALS)
    crates = sorted(p for p in all_pages if p.startswith("crates/"))
    part("Crates", ["bin/ferrosip/README.md"] + [p for p in crates if "/sip-" in p] + [p for p in crates if "/sip-" not in p])
    part("Tools", sorted(p for p in all_pages if p.startswith("tools/")))
    lines.extend(["", "# Examples", ""])
    for p in sorted(p for p in all_pages if p.startswith("examples/") and not p.startswith("examples/scenarios/")):
        item(p)
    item("examples/scenarios/README.md")
    for p in sorted(p for p in all_pages if p.startswith("examples/scenarios/") and p != "examples/scenarios/README.md"):
        item(p, 1)
    missing = [p for p in USING + REFERENCE + INTERNALS if p not in all_pages]
    if missing:
        sys.exit(f"site/build.py: listed in SUMMARY but not found: {missing}")
    if left:
        sys.exit(f"site/build.py: pages missing from SUMMARY.md (add them to a section): {sorted(left)}")
    return "\n".join(lines) + "\n"


def main():
    all_pages = pages()
    shutil.rmtree(SRC, ignore_errors=True)
    linker = Linker(all_pages)
    for p in all_pages:
        with open(os.path.join(ROOT, p), encoding="utf-8") as f:
            text = linker.rewrite(p, f.read())
        dst = os.path.join(SRC, p)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            f.write(text)
    for a in sorted(linker.assets):
        dst = os.path.join(SRC, a)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, a), dst)
    with open(os.path.join(SRC, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write(summary(all_pages))
    for w in linker.warnings:
        print(f"warning: {w}", file=sys.stderr)
    print(f"staged {len(all_pages)} pages and {len(linker.assets)} images into {os.path.relpath(SRC, ROOT)}")


if __name__ == "__main__":
    main()
