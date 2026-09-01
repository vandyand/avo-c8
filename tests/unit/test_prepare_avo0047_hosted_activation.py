from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.main_graduation_ledger import MainLedgerActivation
from avo_correlate.domain.canonical import canonical_bytes
from scripts.prepare_avo0047_hosted_activation import (
    HostedActivationPreparationError,
    main,
    prepare_local_activation_draft_from_files,
)


def _write_candidates(tmp_path: Path) -> tuple[Path, Path, Path]:
    paths: list[Path] = []
    for name in ("authority", "capability", "proof"):
        path = tmp_path / f"{name}.json"
        # These intentionally do not validate as the three ledger DTOs. Local
        # preparation inventories bytes only and must not claim authentication.
        path.write_bytes(canonical_bytes({"unverified_candidate": name}))
        paths.append(path)
    return paths[0], paths[1], paths[2]


def test_file_preparation_records_unverified_inventory_not_an_activation(tmp_path: Path) -> None:
    authority, capability, proof = _write_candidates(tmp_path)
    draft = prepare_local_activation_draft_from_files(
        authority,
        capability,
        proof,
        tmp_path / "local-activation-draft.json",
    )

    assert draft.draft.activation_consumable is False
    assert draft.draft.rooted_verification is False
    assert draft.artifact_path.exists()
    assert [item.artifact_digest for item in draft.draft.candidate_artifacts] == [
        "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (authority, capability, proof)
    ]
    with pytest.raises(ValidationError):
        MainLedgerActivation.model_validate(draft.draft.model_dump(mode="json"))


def test_file_preparation_rejects_noncanonical_input(tmp_path: Path) -> None:
    authority, capability, proof = _write_candidates(tmp_path)
    capability.write_text(
        json.dumps({"unverified_candidate": "capability"}, indent=2), encoding="utf-8"
    )
    with pytest.raises(HostedActivationPreparationError, match="canonical"):
        prepare_local_activation_draft_from_files(
            authority,
            capability,
            proof,
            tmp_path / "local-activation-draft.json",
        )


def test_cli_rejects_arbitrary_module_callable_verifier_flags(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(
            [
                "--controller-authority-file",
                "authority.json",
                "--capability-evidence-file",
                "capability.json",
                "--hosted-rollback-proof-file",
                "proof.json",
                "--output-file",
                "draft.json",
                "--authority-verifier",
                "operator:truth",
            ]
        )
    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert "unrecognized arguments" in captured.err
