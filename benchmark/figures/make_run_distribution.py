"""Per-run recall/F1 distribution figure (strip + box) from repeated-run JSON.

Pure-Python SVG (no matplotlib on the run host). Reads one or more eval_<arm>_*.json
files produced by benchmark/eval.py (each carries
aggregate.<metric>.raw_values = the per-run values) and draws, per arm, a strip
plot of the individual runs plus a box (min / mean / max) so the spread of the
nondeterministic LLM runs is visible.

Usage:
  python benchmark/figures/make_run_distribution.py \
      --metric recall \
      --out benchmark/figures/run_distribution.svg \
      benchmark/results/phaseA/eval_autopsy_*.json \
      benchmark/results/phaseA/eval_chunked-nograph_*.json \
      benchmark/results/phaseA/eval_raw_*.json
"""
from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path


def load_arm(path: Path, metric: str):
    d = json.loads(Path(path).read_text())
    arm = d.get("arm") or d.get("config", {}).get("arm", Path(path).stem)
    vals = d.get("aggregate", {}).get(metric, {}).get("raw_values", [])
    return arm, [v * 100 for v in vals]  # to percent


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_svg(arms: dict, metric: str) -> str:
    # Layout
    W, H = 720, 420
    ml, mr, mt, mb = 70, 30, 50, 70
    plot_w = W - ml - mr
    plot_h = H - mt - mb
    names = list(arms)
    n = max(1, len(names))
    band = plot_w / n

    def x_center(i):
        return ml + band * (i + 0.5)

    def y_for(v):  # v in 0..100
        return mt + plot_h * (1 - v / 100.0)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'font-family="-apple-system,Helvetica,Arial,sans-serif">',
        f'<rect width="{W}" height="{H}" fill="white"/>',
        f'<text x="{W/2}" y="26" text-anchor="middle" font-size="16" '
        f'font-weight="bold">Per-run {_esc(metric)} distribution '
        f'({sum(len(v) for v in arms.values())} runs)</text>',
    ]
    # y gridlines + labels
    for gv in range(0, 101, 20):
        y = y_for(gv)
        parts.append(f'<line x1="{ml}" y1="{y:.1f}" x2="{W-mr}" y2="{y:.1f}" '
                     f'stroke="#eee"/>')
        parts.append(f'<text x="{ml-8}" y="{y+4:.1f}" text-anchor="end" '
                     f'font-size="11" fill="#555">{gv}%</text>')
    colors = ["#2b6cb0", "#c05621", "#2f855a", "#6b46c1", "#b83280"]
    for i, name in enumerate(names):
        vals = arms[name]
        cx = x_center(i)
        col = colors[i % len(colors)]
        if vals:
            vmin, vmax = min(vals), max(vals)
            vmean = sum(vals) / len(vals)
            # box from min..max
            bw = band * 0.42
            parts.append(
                f'<rect x="{cx-bw:.1f}" y="{y_for(vmax):.1f}" width="{2*bw:.1f}" '
                f'height="{max(1,y_for(vmin)-y_for(vmax)):.1f}" fill="{col}" '
                f'fill-opacity="0.10" stroke="{col}" stroke-opacity="0.5"/>')
            # mean line
            parts.append(
                f'<line x1="{cx-bw:.1f}" y1="{y_for(vmean):.1f}" '
                f'x2="{cx+bw:.1f}" y2="{y_for(vmean):.1f}" stroke="{col}" '
                f'stroke-width="2.5"/>')
            # strip points (jittered deterministically)
            for j, v in enumerate(vals):
                jit = (((j * 37) % 11) - 5) / 5.0 * (bw * 0.6)
                parts.append(
                    f'<circle cx="{cx+jit:.1f}" cy="{y_for(v):.1f}" r="4" '
                    f'fill="{col}" fill-opacity="0.75"/>')
            parts.append(
                f'<text x="{cx:.1f}" y="{y_for(vmax)-8:.1f}" text-anchor="middle" '
                f'font-size="11" fill="{col}">{vmean:.0f}% '
                f'[{vmin:.0f}-{vmax:.0f}]</text>')
        # arm label
        parts.append(
            f'<text x="{cx:.1f}" y="{H-mb+22:.1f}" text-anchor="middle" '
            f'font-size="12" font-weight="bold">{_esc(name)}</text>')
        parts.append(
            f'<text x="{cx:.1f}" y="{H-mb+38:.1f}" text-anchor="middle" '
            f'font-size="10" fill="#777">n={len(vals)}</text>')
    # axes
    parts.append(f'<line x1="{ml}" y1="{mt}" x2="{ml}" y2="{H-mb}" stroke="#333"/>')
    parts.append(f'<line x1="{ml}" y1="{H-mb}" x2="{W-mr}" y2="{H-mb}" stroke="#333"/>')
    parts.append('</svg>')
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="eval_<arm>_*.json (globs ok)")
    ap.add_argument("--metric", default="recall", choices=["recall", "precision", "f1"])
    ap.add_argument("--out", type=Path,
                    default=Path("benchmark/figures/run_distribution.svg"))
    args = ap.parse_args()

    paths = []
    for f in args.files:
        paths.extend(sorted(glob.glob(f)))
    arms: dict[str, list] = {}
    for p in paths:
        arm, vals = load_arm(Path(p), args.metric)
        arms.setdefault(arm, [])
        arms[arm].extend(vals)
    if not arms:
        print("no input arms found")
        return
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_svg(arms, args.metric))
    for arm, vals in arms.items():
        print(f"{arm:<18} n={len(vals)} vals={[round(v) for v in vals]}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
