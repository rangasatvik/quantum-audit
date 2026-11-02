"""
"The gap is closing" chart: qubits needed to break RSA-2048 vs. the largest real machines.

Two lines on one log-scale axis (both are counts of physical qubits):
  - orange: published estimates of how many physical qubits an error-corrected quantum
    computer would need to factor a 2048-bit RSA key. They keep falling as algorithms
    and error-correction tricks improve.
  - blue: the largest quantum machines actually built. They keep growing.

Hollow markers are weaker evidence: a resource estimate that so far exists only as a
simulation, and an atom array that has not yet run entangling gates.

Caveat (also printed on the chart): raw qubit counts are not directly comparable.
The estimates assume error-corrected machines with low error rates, while today's
machines are noisy. The chart shows a trend, not a countdown.

Run it from the project root:
    python -m demos.scaling_chart
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # draw to a file instead of opening a window
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "docs" / "scaling.png"

# Colors (checked for color-blind separation and contrast on the light background).
ESTIMATE_COLOR = "#eb6834"  # orange
MACHINE_COLOR = "#2a78d6"  # blue
SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e4e3df"


def year(y: int, month: int) -> float:
    """Turn a year and month into a decimal year for the x-axis (May 2019 -> 2019.33)."""
    return y + (month - 1) / 12


# --- Data ----------------------------------------------------------------------------
# Each entry: (x position, physical qubits, label, solid?). solid=False -> hollow marker.

# Estimated physical qubits to factor RSA-2048.
ESTIMATES = [
    # Gidney & Ekerå, "How to factor 2048 bit RSA integers in 8 hours using 20 million
    # noisy qubits", arXiv:1905.09749 (May 2019), published in Quantum (2021).
    (year(2019, 5), 20_000_000, "~20 million\nGidney & Ekerå", True),
    # Gidney, "How to factor 2048 bit RSA integers with less than a million noisy qubits",
    # arXiv:2505.15917 (May 2025).
    (year(2025, 5), 1_000_000, "<1 million\nGidney", True),
    # Iceberg Quantum (Feb 2026), <100,000 physical qubits using qLDPC codes.
    # Simulation only, not peer reviewed. Via The Quantum Insider:
    # https://thequantuminsider.com/?p=2386320
    (year(2026, 2), 100_000, "<100,000\nIceberg Quantum\n(simulation only)", False),
]

# Largest quantum machines built (physical qubits).
MACHINES = [
    # Google Sycamore, 53 qubits. Arute et al., Nature 574, 505 (Oct 2019).
    (year(2019, 10), 53, "Google Sycamore\n53", True),
    # IBM Eagle, 127 qubits, announced Nov 2021.
    (year(2021, 11), 127, "IBM Eagle\n127", True),
    # IBM Osprey, 433 qubits, announced Nov 2022.
    (year(2022, 11), 433, "IBM Osprey\n433", True),
    # Atom Computing, 1,180 neutral-atom qubits, announced Oct 2023. The first gate-based
    # machine past 1,000 qubits (IBM Condor, 1,121, followed in Dec 2023).
    (year(2023, 10), 1_180, "Atom Computing\n1,180", True),
    # Caltech, 6,100 trapped-atom qubits. Manetsch et al., "A tweezer array with 6100
    # highly coherent atomic qubits", Nature (Sep 2025). Not yet entangled: a qubit
    # array, not a full computer, so it gets a hollow marker.
    (year(2025, 9), 6_100, "Caltech atom array\n6,100 (no entangling\ngates yet)", False),
]

SOURCES = (
    "Sources: estimates from Gidney & Ekerå, arXiv:1905.09749 (2019); Gidney, arXiv:2505.15917 (2025); "
    "Iceberg Quantum via The Quantum Insider (2026).\n"
    "Machines: Google Sycamore, Nature 574 (2019); IBM Eagle (2021) and Osprey (2022) announcements; "
    "Atom Computing announcement (2023); Manetsch et al., Nature (2025).\n"
    "Raw qubit counts are not directly comparable: the estimates assume error-corrected machines "
    "with low error rates, while today's machines are noisy."
)


def _plot_series(ax, points, color, label_offsets):
    """Draw one series: solid line between solid points, dashed into hollow ones."""
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    for i in range(len(points) - 1):
        dashed = not points[i + 1][3]  # dash the segment that leads to weaker evidence
        ax.plot(xs[i : i + 2], ys[i : i + 2], color=color, linewidth=2,
                linestyle=(0, (4, 3)) if dashed else "-", zorder=2)
    for (x, y, text, solid), (dx, dy, ha) in zip(points, label_offsets):
        ax.plot(x, y, marker="o", markersize=8, color=color, zorder=3,
                markerfacecolor=color if solid else SURFACE, markeredgewidth=2,
                markeredgecolor=color)
        ax.annotate(text, (x, y), xytext=(dx, dy), textcoords="offset points", ha=ha,
                    va="center", fontsize=8, color=TEXT_PRIMARY, linespacing=1.15)


def _qubit_label(value, _pos):
    """Format log-axis ticks as 10, 1,000, 100k, 10M instead of 10^3 etc."""
    if value >= 1_000_000:
        return f"{value / 1_000_000:g}M"
    if value >= 100_000:
        return f"{value / 1_000:g}k"
    return f"{value:,.0f}"


def make_scaling_chart(out_path: Path = OUTPUT_PATH) -> Path:
    """Draw the chart and save it as a PNG. Returns the path written."""
    fig, ax = plt.subplots(figsize=(10, 6.2), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)

    # Label offsets (x points, y points, alignment), one per data point, chosen by eye
    # so labels don't collide.
    _plot_series(ax, ESTIMATES, ESTIMATE_COLOR,
                 [(8, 18, "left"), (-10, 14, "right"), (10, 14, "left")])
    _plot_series(ax, MACHINES, MACHINE_COLOR,
                 [(10, -14, "left"), (0, -22, "center"), (0, -22, "center"),
                  (0, -22, "center"), (-10, 22, "right")])

    # Log scale: each gridline is 10x the one below, so 50 and 20 million fit on one axis.
    ax.set_yscale("log")
    ax.set_ylim(10, 100_000_000)
    ax.yaxis.set_major_formatter(FuncFormatter(_qubit_label))
    ax.set_xlim(2018.6, 2027.2)
    ax.set_xticks(range(2019, 2027))
    ax.set_ylabel("Physical qubits (log scale)", color=TEXT_SECONDARY)

    # Recessive grid and axes so the data stands out.
    ax.grid(True, which="major", axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(TEXT_SECONDARY)
    ax.tick_params(colors=TEXT_SECONDARY, labelsize=9)

    ax.set_title("The gap is closing: qubits needed to break RSA-2048 vs. largest machines built",
                 loc="left", fontsize=12, color=TEXT_PRIMARY, pad=12)

    legend_items = [
        Line2D([], [], color=ESTIMATE_COLOR, linewidth=2, marker="o", markersize=7,
               label="Estimated qubits to break RSA-2048"),
        Line2D([], [], color=MACHINE_COLOR, linewidth=2, marker="o", markersize=7,
               label="Largest quantum machine built"),
        Line2D([], [], color=TEXT_SECONDARY, linewidth=0, marker="o", markersize=7,
               markerfacecolor=SURFACE, markeredgewidth=2,
               label="Hollow = simulation only / not yet a full computer"),
    ]
    ax.legend(handles=legend_items, loc="upper right", fontsize=8, frameon=False,
              labelcolor=TEXT_PRIMARY)

    fig.text(0.01, 0.01, SOURCES, fontsize=6.5, color=TEXT_SECONDARY, ha="left", va="bottom",
             linespacing=1.4)
    fig.subplots_adjust(left=0.08, right=0.97, top=0.92, bottom=0.17)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    return out_path


if __name__ == "__main__":
    print(f"Chart saved to {make_scaling_chart()}")
