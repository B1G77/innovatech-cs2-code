import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("functions/soar", "functions/indexer", "detectors"):
    sys.path.insert(0, str(ROOT / sub))

# boto3 clients are created at import time; they need a region but make no calls in these tests.
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def no_office_nodes(monkeypatch):
    """No SSM calls in unit tests: by default no office node is registered."""
    import nodes
    monkeypatch.setattr(nodes, "online_with_tag", lambda key, value: [])
    monkeypatch.setattr(nodes, "find", lambda ip=None, node_id=None: None)
