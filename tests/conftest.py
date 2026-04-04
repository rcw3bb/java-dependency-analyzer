"""
conftest module.

Global pytest configuration and shared fixtures.

Activates ``httpx`` interception for every test so that no test can reach a
real network endpoint by accident.  Tests that legitimately need HTTP
responses must register them via the ``httpx_mock`` fixture from
``pytest-httpx``.

:author: Ron Webb
:since: 1.0.0
"""

import pytest
from pytest_httpx import HTTPXMock

__author__ = "Ron Webb"
__since__ = "1.0.0"


@pytest.fixture(autouse=True)
def _block_real_http(httpx_mock: HTTPXMock) -> None:  # noqa: ARG001
    """
    Activate ``pytest-httpx`` interception for every test so that any
    unmocked ``httpx`` call raises instead of hitting a real server.

    Tests that need HTTP responses should accept ``httpx_mock`` as a
    parameter and register responses before invoking the code under test.

    :author: Ron Webb
    :since: 1.0.0
    """
