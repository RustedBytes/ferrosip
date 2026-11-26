#!/usr/bin/env python3
"""Check every relative link in the built site: the target file exists and,
for `page.html#anchor`, the page has an element with that id.

Usage: python3 site/check_links.py site/book   (exit 1 on broken links)

print.html (all pages in one, with mdBook's own link rewriting) and
404.html (absolute site-url links) are not checked.
"""
import html.parser, os, sys, urllib.parse

SKIP = {"print.html", "404.html"}


class Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids, self.links = set(), []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.add(a["id"])
        if tag == "a" and a.get("name"):
            self.ids.add(a["name"])
        for k in ("href", "src"):
            if a.get(k):
                self.links.append(a[k])


def main(book):
    pages = {}
    for d, _, files in os.walk(book):
        for f in files:
            if f.endswith(".html"):
                p = Page()
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    p.feed(fh.read())
                pages[os.path.relpath(os.path.join(d, f), book)] = p
    broken = []
    for rel, page in sorted(pages.items()):
        if os.path.basename(rel) in SKIP:
            continue
        for link in page.links:
            u = urllib.parse.urlsplit(link)
            if u.scheme or u.netloc or link.startswith(("/", "mailto:", "javascript:")):
                continue
            path = urllib.parse.unquote(u.path)
            target = os.path.normpath(os.path.join(os.path.dirname(rel), path)) if path else rel
            if path and not os.path.exists(os.path.join(book, target)):
                broken.append(f"{rel}: {link} (no file {target})")
                continue
            if u.fragment and target.endswith(".html"):
                tp = pages.get(target)
                frag = urllib.parse.unquote(u.fragment)
                if tp is not None and frag not in tp.ids:
                    broken.append(f"{rel}: {link} (no #{frag} in {target})")
    for b in broken:
        print(b)
    checked = sum(1 for r in pages if os.path.basename(r) not in SKIP)
    print(f"{checked} pages checked, {len(broken)} broken links", file=sys.stderr)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "site/book"))
