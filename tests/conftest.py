"""Shared pytest fixtures."""

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return REPO_ROOT / "fixtures"


@pytest.fixture(scope="session")
def benign_jsonl(fixtures_dir: Path) -> Path:
    path = fixtures_dir / "benign_sample.jsonl"
    assert path.exists(), f"missing fixture: {path}"
    return path


@pytest.fixture(scope="session")
def benign_jsonl_size(benign_jsonl: Path) -> int:
    """Number of non-blank records in the bundled benign fixture."""
    with benign_jsonl.open() as fh:
        return sum(1 for line in fh if line.strip())
