import pytest


@pytest.fixture(autouse=True)
def notebook_in_tmp(tmp_path, monkeypatch):
    """Point the case notebook at a throwaway file, so tests never touch osint.db."""
    path = tmp_path / "notebook.db"
    monkeypatch.setenv("OSINT_DB", str(path))
    return path
