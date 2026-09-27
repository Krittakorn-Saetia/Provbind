"""Read the feature names listed in ml/features.md (the first column of its tables)."""
import re
from pathlib import Path

FEATURES_MD = Path(__file__).resolve().parents[2] / "ml" / "features.md"
VOCABULARY_PATTERN = "pkg.has.<type>/<name>"


def documented_names(text: str | None = None) -> set[str]:
    text = FEATURES_MD.read_text(encoding="utf-8") if text is None else text
    return set(re.findall(r"^\| `([^`]+)` \|", text, flags=re.MULTILINE))


def undocumented(names, documented: set[str]) -> list[str]:
    """Names missing from the doc; vocabulary features are covered by their pattern."""
    return [n for n in names
            if n not in documented and not (n.startswith("pkg.has.") and VOCABULARY_PATTERN in documented)]
