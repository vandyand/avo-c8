"""Focused coverage for API authentication, parsing, health, and error boundaries."""

from pathlib import Path
from typing import Any, cast

import pytest
from fastapi import HTTPException
from starlette.testclient import TestClient

import avo_correlate.api.app as api_module
from tests.conftest import experiment_spec

_parse_if_match = api_module._parse_if_match  # pyright: ignore[reportPrivateUsage]
create_app = api_module.create_app


def test_if_match_parser_accepts_strong_integer_and_rejects_unsafe_forms() -> None:
    assert _parse_if_match('  "12" ') == 12
    assert _parse_if_match("12") == 12
    for value, message in [('W/"2"', "weak"), ("zero", "contain"), ("0", "positive")]:
        with pytest.raises(HTTPException, match=message):
            _parse_if_match(value)


def test_health_readiness_and_authentication_configuration(tmp_path: Path) -> None:
    unconfigured = create_app(tmp_path / "none")
    with cast(Any, TestClient(unconfigured)) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").status_code == 503
        missing = client.post("/v1/experiments", json=experiment_spec().model_dump(mode="json"))
        assert missing.status_code == 422

    configured = create_app(tmp_path / "configured", api_token="correct")
    with cast(Any, TestClient(configured)) as client:
        assert client.get("/readyz").json() == {"status": "ready"}
        spec = experiment_spec().model_dump(mode="json")
        headers = {
            "Authorization": "Bearer wrong",
            "Idempotency-Key": "api-boundary",
            "X-Actor-ID": "operator",
        }
        assert client.post("/v1/experiments", json=spec, headers=headers).status_code == 401
        headers["Authorization"] = "Basic correct"
        assert client.post("/v1/experiments", json=spec, headers=headers).status_code == 401


def test_api_problem_shapes_and_query_validation(tmp_path: Path) -> None:
    api = create_app(tmp_path, api_token="token")
    with cast(Any, TestClient(api)) as client:
        missing = client.get("/v1/runs/no-such-run")
        assert missing.status_code == 404
        body = missing.json()
        assert body["type"].endswith(":not_found")
        assert body["next_action"]
        invalid_after = client.get("/v1/runs/no-such-run/events?after=-1")
        assert invalid_after.status_code == 422
