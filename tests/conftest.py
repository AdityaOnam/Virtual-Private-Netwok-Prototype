"""
tests/conftest.py — pytest fixtures shared across all test modules.
"""

import pytest
from oslab.daemon.ops import FakeOps


@pytest.fixture
def fake_ops() -> FakeOps:
    """
    Return a fresh FakeOps instance.

    Each test gets its own instance so call-tracking state (firewall_calls,
    installed_tunnels, uninstalled_tunnels) never leaks between tests.
    """
    return FakeOps()
