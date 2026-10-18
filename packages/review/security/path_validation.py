"""Secure path validation and traversal prevention for AEGIS AI Code Review."""

from pathlib import Path


def validate_contained_path(
    repo_root: Path,
    candidate_path: str | Path | None,
) -> Path | None:
    """Validates that candidate_path resolves strictly within resolved repo_root.

    Safeguards:
    1. Rejects None, empty, or whitespace-only paths.
    2. Rejects syntactically absolute paths (leading slash, Windows drive letters).
    3. Resolves symlinks and traversal components to prove containment.
    4. Enforces containment via Path.is_relative_to() (never naive string prefix).

    Returns:
        The canonical resolved Path if strictly contained within repo_root,
        or None if the path escapes, traverses out, or is invalid.
    """
    if not candidate_path:
        return None

    raw_str = str(candidate_path).strip()
    if not raw_str:
        return None

    # Syntactic check: reject leading slashes or Windows UNC/drive roots
    if raw_str[0] in ('/', chr(92)):
        return None

    candidate_p = Path(raw_str)
    if candidate_p.is_absolute():
        return None

    resolved_root = repo_root.resolve()
    resolved_candidate = (resolved_root / candidate_p).resolve()

    try:
        if not resolved_candidate.is_relative_to(resolved_root):
            return None
    except (ValueError, AttributeError):
        return None

    return resolved_candidate
