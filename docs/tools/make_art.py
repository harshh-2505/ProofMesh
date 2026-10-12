"""Generate the README artwork (banner and pipeline) as self-contained SVGs.

Run from the repository root:  python docs/tools/make_art.py
The banner's hashprint is the real Merkle root of the demo ledger.
"""

from __future__ import annotations

import colorsys
import math
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent
ROOT_HEX = "2568d3aa681b522f1a53cada2f70fa00062de4262658bd0286ba2b094034113f"
DISPLAY = "Unbounded, 'Arial Black', 'Helvetica Neue', Helvetica, Arial, sans-serif"
SANS = "'Instrument Sans', 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'JetBrains Mono', SFMono-Regular, Menlo, Consolas, monospace"
HOLO = ["#5eead4", "#93c5fd", "#c4b5fd", "#f9a8d4", "#fcd34d", "#bef264", "#5eead4"]

THEMES = {
    "dark": dict(bg="#06080d", bg2="#0d1320", text="#e9eef7", text2="#a6b1c5", text3="#6d7891",
                 engrave="#6ef2cf", engrave_op=0.16, core="#0a0e16", line="#1c2433", accent="#6ef2cf",
                 card="#0f141f"),
    "light": dict(bg="#f2efe7", bg2="#e6e1d4", text="#121722", text2="#4a5468", text3="#7a8398",
                  engrave="#0f766e", engrave_op=0.16, core="#fbfaf6", line="#d6d0c2", accent="#0f766e",
                  card="#fbfaf6"),
}


def lerp_hex(a: str, b: str, t: float) -> str:
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(ca, cb))


def holo_at(t: float) -> str:
    t = t % 1.0
    seg = t * (len(HOLO) - 1)
    i = int(seg)
    return lerp_hex(HOLO[i], HOLO[min(i + 1, len(HOLO) - 1)], seg - i)


def band(cx, cy, base, amp, lobes, copies, wobble, steps, scale=1.0) -> list[str]:
    paths = []
    for i in range(copies):
        phase = (i / copies) * (math.pi * 2) / lobes * 2
        pts = []
        for s in range(steps + 1):
            t = s / steps * math.pi * 2
            r = (base + amp * math.sin(lobes * t + phase) + wobble * math.sin(3 * t + i * 0.4)) * scale
            pts.append(f"{cx + r * math.cos(t):.1f} {cy + r * math.sin(t):.1f}")
        paths.append("M" + "L".join(pts) + "Z")
    return paths


def guilloche(cx, cy, scale, color, opacity) -> str:
    d = []
    d += band(cx, cy, 262, 20, 36, 14, 4, 540, scale)
    d += band(cx, cy, 196, 26, 24, 12, 6, 480, scale)
    d += band(cx, cy, 128, 22, 15, 10, 3, 360, scale)
    d += band(cx, cy, 72, 26, 9, 8, 2, 240, scale)
    body = "".join(f'<path d="{p}"/>' for p in d)
    return f'<g fill="none" stroke="{color}" stroke-opacity="{opacity}" stroke-width="0.7">{body}</g>'


def seal(cx, cy, r, th, hexroot=ROOT_HEX, spin=True) -> str:
    out = [f'<g transform="translate({cx} {cy})">']
    out.append(f'<circle r="{r + 10}" fill="none" stroke="{th["text3"]}" stroke-opacity=".35" stroke-dasharray="1.5 6"/>')
    # holographic foil: 90 wedges sweeping through the palette, slowly rotating
    wedges = []
    n = 90
    for i in range(n):
        a0, a1 = 2 * math.pi * i / n, 2 * math.pi * (i + 1.08) / n
        x0, y0, x1, y1 = r * math.cos(a0), r * math.sin(a0), r * math.cos(a1), r * math.sin(a1)
        wedges.append(f'<path d="M0 0L{x0:.2f} {y0:.2f}A{r} {r} 0 0 1 {x1:.2f} {y1:.2f}Z" fill="{holo_at(i / n)}"/>')
    anim = ('<animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="24s" '
            'repeatCount="indefinite"/>') if spin else ""
    out.append(f'<g>{"".join(wedges)}{anim}</g>')
    out.append(f'<circle r="{r}" fill="url(#sheen)"/>')
    # hashprint bars, engraved in the core colour
    inner = r * 0.52
    maxlen = r * 0.36
    for i, ch in enumerate(hexroot):
        v = int(ch, 16)
        ln = maxlen * (0.18 + 0.82 * v / 15)
        ang = i / 64 * 360
        out.append(f'<rect x="-1.7" y="{-(inner + ln):.1f}" width="3.4" height="{ln:.1f}" rx="1.4" '
                   f'fill="{th["core"]}" transform="rotate({ang:.2f})"/>')
    out.append(f'<circle r="{r * 0.93:.1f}" fill="none" stroke="{th["core"]}" stroke-width="1.2" stroke-dasharray="1.2 4.4" opacity=".7"/>')
    out.append(f'<circle r="{inner - 4:.1f}" fill="{th["core"]}"/>')
    k = inner * 0.42
    out.append(f'<path d="M{-k:.1f} {k * 0.05:.1f}L{-k * 0.25:.1f} {k * 0.75:.1f}L{k:.1f} {-k * 0.6:.1f}" fill="none" '
               f'stroke="url(#holo)" stroke-width="{inner * 0.16:.1f}" stroke-linecap="round" stroke-linejoin="round"/>')
    out.append("</g>")
    return "".join(out)


def defs(th) -> str:
    stops = "".join(f'<stop offset="{i / (len(HOLO) - 1):.3f}" stop-color="{c}"/>' for i, c in enumerate(HOLO))
    return (f'<defs><linearGradient id="holo" x1="0" y1="0" x2="1" y2="0">{stops}</linearGradient>'
            f'<linearGradient id="bgg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{th["bg"]}"/>'
            f'<stop offset="1" stop-color="{th["bg2"]}"/></linearGradient>'
            '<radialGradient id="sheen" cx=".3" cy=".25" r=".8"><stop offset="0" stop-color="#fff" stop-opacity=".45"/>'
            '<stop offset=".5" stop-color="#fff" stop-opacity="0"/></radialGradient>'
            '<clipPath id="frame"><rect width="1280" height="440" rx="28"/></clipPath></defs>')


def banner(name: str) -> str:
    th = THEMES[name]
    chips = ["Ed25519", "FastCDC", "RFC 6962 Merkle", "Signed lineage", "Hash-chained log"]
    chip_svg, x = [], 72
    for c in chips:
        w = 16 + len(c) * 7.6
        chip_svg.append(f'<g transform="translate({x:.0f} 334)"><rect width="{w:.0f}" height="30" rx="15" fill="{th["card"]}" '
                        f'stroke="{th["line"]}"/><text x="{w / 2:.0f}" y="20" text-anchor="middle" font-family="{MONO}" '
                        f'font-size="12" fill="{th["text2"]}">{c}</text></g>')
        x += w + 10
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 440" width="1280" height="440" role="img" aria-label="ProofMesh: every dataset carries its own proof">
{defs(th)}
<g clip-path="url(#frame)">
<rect width="1280" height="440" fill="url(#bgg)"/>
{guilloche(1070, 220, 0.78, th["engrave"], th["engrave_op"])}
<rect x="-200" y="0" width="160" height="440" fill="url(#holo)" opacity=".10" transform="skewX(-18)">
  <animate attributeName="x" values="-260;1480" dur="7s" repeatCount="indefinite"/>
</rect>
{seal(1070, 220, 140, th)}
<text x="72" y="118" font-family="{MONO}" font-size="14" letter-spacing="3.5" fill="{th["accent"]}" font-weight="600">CRYPTOGRAPHICALLY VERIFIABLE DATA MESH</text>
<text x="68" y="212" font-family="{DISPLAY}" font-size="92" font-weight="800" letter-spacing="-3" fill="{th["text"]}">Proof<tspan fill="url(#holo)">Mesh</tspan></text>
<text x="72" y="262" font-family="{SANS}" font-size="26" fill="{th["text2"]}">Every dataset carries its own proof.</text>
<text x="72" y="298" font-family="{SANS}" font-size="17" fill="{th["text3"]}">Change one byte and it names what changed and every report that inherited it.</text>
{"".join(chip_svg)}
<text x="72" y="404" font-family="{MONO}" font-size="11" fill="{th["text3"]}">ring = Merkle root of the demo ledger: {ROOT_HEX}</text>
</g>
</svg>
'''


STEPS = [
    ("Publish", "Signed data contract", "M-11 -15h22v30h-22zM-6 -7h12M-6 0h12M-6 7h8"),
    ("Chunk", "FastCDC + SHA-256", "M-17 -7h8v14h-8zM-6 -7h12v14h-12zM9 -7h8v14h-8z"),
    ("Seal", "Merkle root, signed", "M0 -14v0M-10 -2v0M10 -2v0M0 -14L-10 -2M0 -14L10 -2M-10 -2L-15 12M-10 -2L-5 12M10 -2L5 12M10 -2L15 12"),
    ("Derive", "Lineage pinned to roots", "M-12 0L10 -10M-12 0L10 10"),
    ("Verify", "Pinned trust, replay", "M0 -16L13 -11v9c0 8-6 14-13 17C-7 12-13 6-13 -2v-9zM-6 0l4 4 8-9"),
]


def pipeline(name: str) -> str:
    th = THEMES[name]
    w, h = 1280, 250
    gap = (w - 280) / (len(STEPS) - 1)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
             f'aria-label="Publish, chunk, seal, derive, verify">', defs(th),
             f'<rect width="{w}" height="{h}" rx="24" fill="url(#bgg)"/>',
             f'<line x1="140" y1="96" x2="{w - 140}" y2="96" stroke="url(#holo)" stroke-width="3" stroke-opacity=".7"/>',
             f'<circle r="6" fill="{th["accent"]}"><animateMotion dur="5s" repeatCount="indefinite" path="M140 96H{w - 140}"/></circle>']
    for i, (title, sub, icon) in enumerate(STEPS):
        x = 140 + i * gap
        dots = ""
        if title == "Derive":
            dots = "".join(f'<circle cx="{px}" cy="{py}" r="4" fill="{th["card"]}" stroke="{th["accent"]}" stroke-width="2"/>'
                           for px, py in [(-12, 0), (10, -10), (10, 10)])
        if title == "Seal":
            dots = "".join(f'<circle cx="{px}" cy="{py}" r="3.2" fill="{th["accent"]}"/>' for px, py in
                           [(0, -14), (-10, -2), (10, -2), (-15, 12), (-5, 12), (5, 12), (15, 12)])
        parts.append(
            f'<g transform="translate({x:.0f} 96)">'
            f'<rect x="-40" y="-40" width="80" height="80" rx="24" fill="{th["card"]}" stroke="{th["line"]}" stroke-width="1.5"/>'
            f'<g transform="scale(1.35)"><path d="{icon}" fill="none" stroke="{th["accent"]}" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round"/>{dots}</g>'
            f'<circle cx="38" cy="-38" r="13" fill="{th["text"]}"/><text x="38" y="-33.5" text-anchor="middle" '
            f'font-family="{MONO}" font-size="12" font-weight="700" fill="{th["bg"]}">{i + 1}</text>'
            f'<text y="78" text-anchor="middle" font-family="{DISPLAY}" font-size="20" font-weight="700" fill="{th["text"]}">{title}</text>'
            f'<text y="104" text-anchor="middle" font-family="{SANS}" font-size="15" fill="{th["text2"]}">{sub}</text></g>')
    parts.append("</svg>\n")
    return "".join(parts)


if __name__ == "__main__":
    for theme in THEMES:
        (DOCS / f"banner-{theme}.svg").write_text(banner(theme))
        (DOCS / f"pipeline-{theme}.svg").write_text(pipeline(theme))
    print("wrote", sorted(p.name for p in DOCS.glob("*.svg")))
