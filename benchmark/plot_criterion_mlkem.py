#!/usr/bin/env python3
"""Plot ML-KEM Criterion benchmark throughput.

Expected Criterion layout:

    target/criterion/{keygen,encaps,decaps}/{mlkem-native,jkem}/mlkem-*/new/
        benchmark.json
        estimates.json

Criterion's mean estimate is nanoseconds per iteration. This script can convert
that to operations per second or combine it with Criterion's configured
throughput bytes to draw MB/s.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
from pathlib import Path

# Matplotlib may try to write cache files under ~/.config, which is not always
# writable in CI or sandboxed environments.
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

import matplotlib.pyplot as plt

OPERATIONS = ("keygen", "encaps", "decaps")
IMPLEMENTATIONS = ("mlkem-native", "jkem")
IMPLEMENTATION_LABELS = {
    "mlkem-native": "mlkem-native",
    "jkem": "our implementation",
}
COLORS = {
    "mlkem-native": "#90c9e6",
    "jkem": "#126784",
}
PARAM_RE = re.compile(r"mlkem-(\d+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ML-KEM throughput bar graphs from Criterion output."
    )
    parser.add_argument(
        "--criterion-dir",
        type=Path,
        default=Path("target/criterion"),
        help="Criterion output directory. Default: target/criterion",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output image path for a single graph. Extension controls format, "
            "e.g. .png, .svg, .pdf. If omitted, writes both throughput and ops graphs."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("target/criterion"),
        help="Output directory when writing both graphs. Default: target/criterion",
    )
    parser.add_argument(
        "--unit",
        choices=("MB/s", "ops/s", "kops/s", "mops/s"),
        default=None,
        help="Generate only one graph with this unit. Default: write MB/s and kops/s graphs.",
    )
    parser.add_argument(
        "--same-y-axis",
        action="store_true",
        help="Use the same Y-axis limit for all three operations.",
    )
    parser.add_argument(
        "--no-error-bars",
        action="store_true",
        help="Hide 95%% confidence interval error bars.",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Figure title for single-graph mode. Defaults depend on the selected unit.",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parameter_size(value: str) -> int | None:
    match = PARAM_RE.search(value)
    if not match:
        return None
    return int(match.group(1))


def unit_scale(unit: str) -> float:
    return {
        "MB/s": 1_000_000.0,
        "ops/s": 1.0,
        "kops/s": 1_000.0,
        "mops/s": 1_000_000.0,
    }[unit]


def estimate_to_ops_per_second(ns_per_iter: float) -> float:
    if ns_per_iter <= 0:
        return math.nan
    return 1_000_000_000.0 / ns_per_iter


def benchmark_bytes_per_iter(benchmark: dict) -> float | None:
    throughput = benchmark.get("throughput")
    if not isinstance(throughput, dict):
        return None
    bytes_decimal = throughput.get("BytesDecimal")
    if bytes_decimal is None:
        return None
    return float(bytes_decimal)


def estimate_to_throughput(
    ns_per_iter: float, scale: float, bytes_per_iter: float | None
) -> float:
    ops_per_second = estimate_to_ops_per_second(ns_per_iter)
    if bytes_per_iter is not None:
        return (ops_per_second * bytes_per_iter) / scale
    return ops_per_second / scale


def collect_results(criterion_dir: Path, unit: str, scale: float) -> dict:
    results: dict[str, dict[str, dict[int, dict[str, float]]]] = {
        op: {impl: {} for impl in IMPLEMENTATIONS} for op in OPERATIONS
    }

    for operation in OPERATIONS:
        for impl in IMPLEMENTATIONS:
            impl_dir = criterion_dir / operation / impl
            if not impl_dir.exists():
                continue

            for benchmark_json in impl_dir.glob("mlkem-*/new/benchmark.json"):
                benchmark = load_json(benchmark_json)
                size = parameter_size(benchmark.get("value_str", ""))
                if size is None:
                    size = parameter_size(str(benchmark_json))
                if size is None:
                    continue

                estimates_path = benchmark_json.with_name("estimates.json")
                if not estimates_path.exists():
                    continue
                estimates = load_json(estimates_path)
                mean = estimates["mean"]
                ci = mean["confidence_interval"]
                bytes_per_iter = (
                    benchmark_bytes_per_iter(benchmark) if unit == "MB/s" else None
                )

                point = estimate_to_throughput(
                    mean["point_estimate"], scale, bytes_per_iter
                )
                lower = estimate_to_throughput(ci["upper_bound"], scale, bytes_per_iter)
                upper = estimate_to_throughput(ci["lower_bound"], scale, bytes_per_iter)
                results[operation][impl][size] = {
                    "point": point,
                    "err_low": max(0.0, point - lower),
                    "err_high": max(0.0, upper - point),
                }

    return results


def ordered_sizes(results: dict) -> list[int]:
    sizes = set()
    for operation in OPERATIONS:
        for impl in IMPLEMENTATIONS:
            sizes.update(results[operation][impl].keys())
    return sorted(sizes)


def add_missing_label(ax, x: float, text: str) -> None:
    ax.text(
        x,
        0.008,
        text,
        transform=ax.get_xaxis_transform(),
        rotation=0,
        ha="center",
        va="bottom",
        fontsize=8,
        color="#6b7280",
        clip_on=False,
        zorder=5,
    )


def format_bar_value(value: float, unit: str) -> str:
    if unit == "ops/s":
        return f"{value:.0f}"
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def default_title(unit: str) -> str:
    if unit == "MB/s":
        return "ML-KEM Data Throughput"
    return "ML-KEM Operation Throughput"


def default_output_path(output_dir: Path, unit: str) -> Path:
    if unit == "MB/s":
        return output_dir / "mlkem-throughput-mbps.png"
    normalized = unit.replace("/", "-")
    return output_dir / f"mlkem-throughput-{normalized}.png"


def unit_output_path(output: Path, unit: str) -> Path:
    if unit == "MB/s":
        suffix = "mbps"
    else:
        suffix = unit.replace("/", "-")
    return output.with_name(f"{output.stem}-{suffix}{output.suffix}")


def plot(
    results: dict,
    sizes: list[int],
    criterion_dir: Path,
    output: Path,
    unit: str,
    title: str,
    same_y_axis: bool,
    no_error_bars: bool,
) -> None:
    if not sizes:
        raise SystemExit(f"No benchmark results found under {criterion_dir}")

    fig, axes = plt.subplots(1, 3, figsize=(13.5, 5.2))
    fig.suptitle(title, fontsize=16, fontweight="semibold")

    width = 0.34
    x_positions = list(range(len(sizes)))
    y_max = 0.0

    for ax, operation in zip(axes, OPERATIONS):
        for offset, impl in ((-width / 2, "mlkem-native"), (width / 2, "jkem")):
            points = []
            err_low = []
            err_high = []
            missing = []

            for size in sizes:
                datum = results[operation][impl].get(size)
                if datum is None:
                    points.append(0.0)
                    err_low.append(0.0)
                    err_high.append(0.0)
                    missing.append(size)
                    continue
                points.append(datum["point"])
                err_low.append(datum["err_low"])
                err_high.append(datum["err_high"])
                y_max = max(y_max, datum["point"] + datum["err_high"])

            bar_x = [x + offset for x in x_positions]
            yerr = None if no_error_bars else [err_low, err_high]
            bars = ax.bar(
                bar_x,
                points,
                width=width,
                label=IMPLEMENTATION_LABELS[impl],
                color=COLORS[impl],
                edgecolor="#111827",
                linewidth=0.4,
                yerr=yerr,
                capsize=3 if yerr else 0,
            )

            for bar, point, high_err in zip(bars, points, err_high):
                if point <= 0:
                    continue
                ax.annotate(
                    format_bar_value(point, unit),
                    xy=(bar.get_x() + bar.get_width() / 2, point + high_err),
                    xytext=(0, 4),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=7,
                    color="#374151",
                )

            for size in missing:
                add_missing_label(ax, x_positions[sizes.index(size)] + offset, "n/a")

        ax.set_title(operation.capitalize(), fontsize=12, fontweight="semibold")
        ax.set_xticks(x_positions, [str(size) for size in sizes])
        ax.set_xlabel("ML-KEM parameter set")
        ax.set_ylabel(f"Throughput ({unit})")
        ax.grid(axis="y", color="#e5e7eb", linewidth=0.8)
        ax.set_axisbelow(True)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)

    if same_y_axis and y_max > 0:
        for ax in axes:
            ax.set_ylim(0, y_max * 1.12)
    else:
        for ax in axes:
            _, top = ax.get_ylim()
            ax.set_ylim(0, top * 1.08)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="lower center",
        ncols=2,
        bbox_to_anchor=(0.5, 0.025),
        frameon=False,
    )
    fig.subplots_adjust(left=0.07, right=0.99, top=0.84, bottom=0.2, wspace=0.28)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(output), dpi=200, bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)


def main() -> None:
    args = parse_args()
    units = (args.unit,) if args.unit else ("MB/s", "kops/s")

    for unit in units:
        if args.output and args.unit:
            output = args.output
        elif args.output:
            output = unit_output_path(args.output, unit)
        else:
            output = default_output_path(args.output_dir, unit)
        title = args.title if args.title else default_title(unit)
        scale = unit_scale(unit)
        results = collect_results(args.criterion_dir, unit, scale)
        sizes = ordered_sizes(results)
        plot(
            results,
            sizes,
            args.criterion_dir,
            output,
            unit,
            title,
            args.same_y_axis,
            args.no_error_bars,
        )
        print(f"Wrote {output}")


if __name__ == "__main__":
    main()
