"""eval/plots.py writes every figure from the committed comparison summary (needs matplotlib)."""
import pytest

pytest.importorskip("matplotlib")

from eval import plots


def test_all_figures_from_the_summary(tmp_path):
    assert plots.main(["--comparison", "docs/figures/data/comparison-2026-10-01.json", "--out", str(tmp_path)]) == 0
    for name in ("comparison-metrics", "comparison-per-scenario", "desfam-anomaly-fractions",
                 "scored-runs-history", "mla-capabilities"):
        assert (tmp_path / f"{name}.png").stat().st_size > 10_000
        assert (tmp_path / f"{name}.svg").exists()


def test_history_alone_without_a_comparison(tmp_path):
    assert plots.main(["--out", str(tmp_path)]) == 0
    assert (tmp_path / "scored-runs-history.png").exists()
