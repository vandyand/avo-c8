"""Immutable, controller-verified journal for the C7 offline drill.

The contracts in :mod:`avo_correlate.contracts.main_graduation_offline_drill`
are deliberately data-only.  This module is the durability boundary around
those contracts: indexes are create-once pointers into a content-addressed
store and every public read reconstructs the complete dependency closure.
"""

# The journal dispatches across three Pydantic model classes at one dynamic
# persistence boundary.  Keep these implementation diagnostics from obscuring
# the strongly typed public methods.
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false

from __future__ import annotations

import errno
import inspect
import json
import os
from pathlib import Path
from typing import Any, Protocol

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_DRILL_VECTOR_IDS,
    MainGraduationOfflineDrillCaseResult,
    MainGraduationOfflineDrillEvidenceRef,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineDrillResult,
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes


class MainGraduationOfflineDrillJournalError(RuntimeError):
    """The C7 journal is missing, malformed, unverifiable, or conflicting."""


class MainGraduationOfflineDrillRecordConflictError(MainGraduationOfflineDrillJournalError):
    """A create-once identity is already bound to different bytes."""


class MainGraduationOfflineDrillAuthorityVerifier(Protocol):
    """Controller-owned, fail-closed verification boundary.

    The third argument to ``verify_case_result`` is the tuple of typed
    evidence references reconstructed from the child artifacts on disk.  The
    journal never passes caller-owned child objects as evidence.
    """

    def verify_plan(self, plan: MainGraduationOfflineDrillPlan) -> object: ...

    def verify_case_result(
        self,
        case_result: MainGraduationOfflineDrillCaseResult,
        plan: MainGraduationOfflineDrillPlan,
        evidence: tuple[MainGraduationOfflineDrillEvidenceRef, ...],
    ) -> object: ...

    def verify_result(
        self,
        result: MainGraduationOfflineDrillResult,
        plan: MainGraduationOfflineDrillPlan,
        cases: tuple[MainGraduationOfflineDrillCaseResult, ...],
    ) -> object: ...


# Shorter names are useful to callers and mirror the other artifact journals.
MainGraduationOfflineDrillVerifier = MainGraduationOfflineDrillAuthorityVerifier
OfflineDrillAuthorityVerifier = MainGraduationOfflineDrillAuthorityVerifier

_DEFAULT_MAX_RECORD_BYTES = 8 * 1024 * 1024
_MAX_INDEX_BYTES = 1024 * 1024
_MEDIA = "application/vnd.avo.main-graduation-offline-drill"
_KINDS = ("plan", "case", "result")
_ROLE_FOR_KIND = {kind: f"main-graduation-offline-drill-{kind}" for kind in _KINDS}
_MEDIA_FOR_KIND = {kind: f"{_MEDIA}-{kind}+json" for kind in _KINDS}


class MainGraduationOfflineDrillJournal:
    """Create-once filesystem journal for one C7 operation namespace."""

    def __init__(
        self,
        root: Path,
        authority_verifier: MainGraduationOfflineDrillAuthorityVerifier | None = None,
        *,
        verifier: MainGraduationOfflineDrillAuthorityVerifier | None = None,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = _DEFAULT_MAX_RECORD_BYTES,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        if authority_verifier is not None and verifier is not None:
            raise ValueError("supply only one C7 authority verifier")
        self._root = root.resolve()
        self._indexes = self._root / "main-graduation-offline-drill-v1"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._verifier = authority_verifier if authority_verifier is not None else verifier
        self._max = max_record_bytes

    @property
    def root(self) -> Path:
        return self._root

    @property
    def artifact_store(self) -> FilesystemArtifactStore:
        return self._store

    def delete_artifact(self, digest: str) -> bool:
        """Recovery/test seam; deleting a referenced object makes reads fail closed."""

        return self._store.delete(digest)

    # ---- public writes -------------------------------------------------

    def record_plan(self, plan: MainGraduationOfflineDrillPlan) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineDrillPlan, plan, "plan")
        self._verify("plan", checked)
        data = canonical_bytes(checked)
        index = self._plan_index(checked.operation_id)
        existing = self._replay_if_existing("plan", index, data)
        if existing is not None:
            return existing
        reference = self._put("plan", data)
        return self._create_once(index, reference, data, "plan")

    record_plan_once = record_plan

    def record_case_result(self, case_result: MainGraduationOfflineDrillCaseResult) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineDrillCaseResult, case_result, "case")
        plan_loaded = self._read_plan(checked.root_operation_id)
        if plan_loaded is None:
            raise MainGraduationOfflineDrillJournalError("case requires a durable plan")
        plan, _ = plan_loaded
        self._bind_case_to_plan(checked, plan)
        evidence = self._read_evidence(checked, plan)
        self._verify("case", checked, plan, evidence)
        data = canonical_bytes(checked)
        index = self._case_index(checked.root_operation_id, checked.case_id, checked.vector_id)
        existing = self._replay_if_existing("case", index, data)
        if existing is not None:
            return existing
        reference = self._put("case", data)
        return self._create_once(
            index,
            reference,
            data,
            "case",
        )

    record_case = record_case_result
    record_case_result_once = record_case_result

    def record_result(self, result: MainGraduationOfflineDrillResult) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineDrillResult, result, "result")
        plan_loaded = self._read_plan(checked.operation_id)
        if plan_loaded is None:
            raise MainGraduationOfflineDrillJournalError("aggregate requires a durable plan")
        plan, _ = plan_loaded
        self._bind_result_to_plan(checked, plan)
        durable = self._load_complete_cases(plan)
        if tuple(item[0] for item in durable) != checked.cases:
            raise MainGraduationOfflineDrillJournalError(
                "aggregate is not identical to the complete durable case matrix"
            )
        self._verify("result", checked, plan, tuple(item[0] for item in durable))
        data = canonical_bytes(checked)
        index = self._result_index(checked.operation_id)
        existing = self._replay_if_existing("result", index, data)
        if existing is not None:
            return existing
        reference = self._put("result", data)
        return self._create_once(index, reference, data, "result")

    record_aggregate_result = record_result
    record_result_once = record_result

    # ---- public reads --------------------------------------------------

    def read_plan(
        self, operation_id: str
    ) -> tuple[MainGraduationOfflineDrillPlan, ArtifactRef] | None:
        return self._read_plan(operation_id)

    def read_case_result(
        self, root_operation_id: str, case_id: str, vector_id: str | None = None
    ) -> tuple[MainGraduationOfflineDrillCaseResult, ArtifactRef] | None:
        if vector_id is None:
            # A case id alone is intentionally only accepted when exactly one
            # durable vector exists; callers cannot use this to skip coverage.
            matches = []
            for candidate in FROZEN_OFFLINE_DRILL_VECTOR_IDS.get(case_id, ()):
                loaded = self._read_case(root_operation_id, case_id, candidate)
                if loaded is not None:
                    matches.append(loaded)
            if not matches:
                return None
            if len(matches) != 1:
                raise MainGraduationOfflineDrillJournalError(
                    "case id is ambiguous; vector id is required"
                )
            return matches[0]
        return self._read_case(root_operation_id, case_id, vector_id)

    read_case = read_case_result

    def read_result(
        self, operation_id: str
    ) -> tuple[MainGraduationOfflineDrillResult, ArtifactRef] | None:
        index = self._result_index(operation_id)
        loaded = self._read_indexed("result", index, MainGraduationOfflineDrillResult)
        if loaded is None:
            return None
        result, reference = loaded
        plan_loaded = self._read_plan(result.operation_id)
        if plan_loaded is None:
            raise MainGraduationOfflineDrillJournalError("result has no durable plan")
        plan, _ = plan_loaded
        self._bind_result_to_plan(result, plan)
        durable = self._load_complete_cases(plan)
        if tuple(item[0] for item in durable) != result.cases:
            raise MainGraduationOfflineDrillJournalError("aggregate durable case closure mismatch")
        self._verify("result", result, plan, tuple(item[0] for item in durable))
        return result, reference

    read_aggregate_result = read_result

    # ---- dependency and evidence checks -------------------------------

    def _plan_index(self, operation_id: str) -> Path:
        return self._indexes / "plan" / f"{operation_id.removeprefix('sha256:')}.json"

    def _case_index(self, root_operation_id: str, case_id: str, vector_id: str) -> Path:
        return (
            self._indexes
            / "case"
            / root_operation_id.removeprefix("sha256:")
            / case_id
            / f"{vector_id}.json"
        )

    def _result_index(self, operation_id: str) -> Path:
        return self._indexes / "result" / f"{operation_id.removeprefix('sha256:')}.json"

    def _read_plan(
        self, operation_id: str
    ) -> tuple[MainGraduationOfflineDrillPlan, ArtifactRef] | None:
        loaded = self._read_indexed(
            "plan", self._plan_index(operation_id), MainGraduationOfflineDrillPlan
        )
        if loaded is None:
            return None
        plan, ref = loaded
        if plan.operation_id != operation_id:
            raise MainGraduationOfflineDrillJournalError("plan identity does not match index")
        self._verify("plan", plan)
        return plan, ref

    def _read_case(
        self, root_operation_id: str, case_id: str, vector_id: str
    ) -> tuple[MainGraduationOfflineDrillCaseResult, ArtifactRef] | None:
        loaded = self._read_indexed(
            "case",
            self._case_index(root_operation_id, case_id, vector_id),
            MainGraduationOfflineDrillCaseResult,
        )
        if loaded is None:
            return None
        case, ref = loaded
        if (
            case.root_operation_id != root_operation_id
            or case.case_id != case_id
            or case.vector_id != vector_id
        ):
            raise MainGraduationOfflineDrillJournalError("case identity does not match index")
        plan_loaded = self._read_plan(root_operation_id)
        if plan_loaded is None:
            raise MainGraduationOfflineDrillJournalError("case has no durable plan")
        plan, _ = plan_loaded
        self._bind_case_to_plan(case, plan)
        evidence = self._read_evidence(case, plan)
        self._verify("case", case, plan, evidence)
        return case, ref

    def _load_complete_cases(
        self, plan: MainGraduationOfflineDrillPlan
    ) -> list[tuple[MainGraduationOfflineDrillCaseResult, ArtifactRef]]:
        loaded: list[tuple[MainGraduationOfflineDrillCaseResult, ArtifactRef]] = []
        for case_id, vectors in (
            (item.case_id, tuple(vector.vector_id for vector in item.vectors))
            for item in plan.cases
        ):
            for vector_id in vectors:
                item = self._read_case(plan.operation_id, case_id, vector_id)
                if item is None:
                    raise MainGraduationOfflineDrillJournalError(
                        f"missing durable case/vector: {case_id}/{vector_id}"
                    )
                loaded.append(item)
        # Detect unexpected case index entries as well as omissions.  An
        # extra index is never harmless because the frozen matrix is exact.
        case_root = self._indexes / "case" / plan.operation_id.removeprefix("sha256:")
        if case_root.is_dir():
            expected = {
                case_id + "/" + vector_id
                for case_id, vectors in (
                    (item.case_id, tuple(vector.vector_id for vector in item.vectors))
                    for item in plan.cases
                )
                for vector_id in vectors
            }
            actual = {
                path.parent.name + "/" + path.stem
                for path in case_root.glob("*/*.json")
                if path.is_file()
            }
            if actual != expected:
                raise MainGraduationOfflineDrillJournalError("durable case index has extra entries")
        return loaded

    def _read_evidence(
        self,
        case: MainGraduationOfflineDrillCaseResult,
        plan: MainGraduationOfflineDrillPlan,
    ) -> tuple[MainGraduationOfflineDrillEvidenceRef, ...]:
        seen_digests: set[str] = set()
        seen_links: set[str] = set()
        result: list[MainGraduationOfflineDrillEvidenceRef] = []
        required = ("c4", "c5", "c6", "provider", "rollback", "ledger", "verifier")
        for ref in case.evidence_artifacts:
            if ref.digest in seen_digests:
                raise MainGraduationOfflineDrillJournalError("duplicate evidence artifact")
            seen_digests.add(ref.digest)
            role = ref.role.casefold()
            kind = next((value for value in required if value in role), None)
            if kind is None:
                raise MainGraduationOfflineDrillJournalError("untyped C7 evidence role")
            if (
                not ref.media_type.casefold().endswith("+json")
                and ref.media_type.casefold() != "application/json"
            ):
                raise MainGraduationOfflineDrillJournalError("C7 evidence must be JSON")
            try:
                raw = self._store.read_bytes(ref)
                payload = _strict_loads(raw)
                if canonical_bytes(payload) != raw or not isinstance(payload, dict):
                    raise ValueError("evidence is not canonical JSON object")
            except Exception as exc:
                raise MainGraduationOfflineDrillJournalError(
                    "evidence artifact is unverifiable"
                ) from exc
            binding = _binding(payload)
            if binding.get("operation_id") != case.operation_id:
                raise MainGraduationOfflineDrillJournalError("evidence operation binding mismatch")
            if binding.get("root_operation_id", plan.operation_id) != plan.operation_id:
                raise MainGraduationOfflineDrillJournalError("evidence root binding mismatch")
            if binding.get("case_id") != case.case_id or binding.get("vector_id") != case.vector_id:
                raise MainGraduationOfflineDrillJournalError(
                    "evidence case/vector binding mismatch"
                )
            link = binding.get("link_id")
            if not isinstance(link, str) or not link or link in seen_links:
                raise MainGraduationOfflineDrillJournalError("evidence link ids must be unique")
            seen_links.add(link)
            # A typed wrapper is recreated from the exact reloaded ref.  It
            # is never accepted from a caller as an authority substitute.
            result.append(
                MainGraduationOfflineDrillEvidenceRef(
                    evidence_type=kind, artifact=ref, evidence_digest=ref.digest
                )
            )
        if any(
            not any(kind in ref.artifact.role.casefold() for ref in result) for kind in required
        ):
            raise MainGraduationOfflineDrillJournalError("evidence closure is incomplete")
        return tuple(result)

    # ---- low-level durable primitives ---------------------------------

    def _put(self, kind: str, data: bytes) -> ArtifactRef:
        return self._store.put_bytes(
            data,
            media_type=_MEDIA_FOR_KIND[kind],
            role=_ROLE_FOR_KIND[kind],
            max_bytes=self._max,
        )

    def _replay_if_existing(self, kind: str, index: Path, data: bytes) -> ArtifactRef | None:
        """Return an exact existing record without touching the CAS or index."""

        if not index.is_file():
            return None
        loaded = self._read_indexed(
            kind,
            index,
            {
                "plan": MainGraduationOfflineDrillPlan,
                "case": MainGraduationOfflineDrillCaseResult,
                "result": MainGraduationOfflineDrillResult,
            }[kind],
        )
        if loaded is None or self._store.read_bytes(loaded[1]) != data:
            raise MainGraduationOfflineDrillRecordConflictError(
                f"conflicting {kind} record"
            ) from None
        return loaded[1]

    def _create_once(
        self, index: Path, reference: ArtifactRef, data: bytes, kind: str
    ) -> ArtifactRef:
        payload = canonical_bytes(reference)
        if len(payload) > _MAX_INDEX_BYTES:
            raise MainGraduationOfflineDrillJournalError("index reference is too large")
        existing = self._replay_if_existing(kind, index, data)
        if existing is not None:
            return existing
        index.parent.mkdir(parents=True, exist_ok=True)
        try:
            with index.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(index.parent)
            return reference
        except FileExistsError:
            loaded = self._read_indexed(
                kind,
                index,
                {
                    "plan": MainGraduationOfflineDrillPlan,
                    "case": MainGraduationOfflineDrillCaseResult,
                    "result": MainGraduationOfflineDrillResult,
                }[kind],
            )
            if loaded is None or self._store.read_bytes(loaded[1]) != data:
                raise MainGraduationOfflineDrillRecordConflictError(
                    f"conflicting {kind} record"
                ) from None
            return loaded[1]

    def _read_indexed(
        self, kind: str, index: Path, model: type[Any]
    ) -> tuple[Any, ArtifactRef] | None:
        if not index.is_file():
            return None
        try:
            raw_index = index.read_bytes()
            if len(raw_index) > _MAX_INDEX_BYTES:
                raise ValueError("index too large")
            value = _strict_loads(raw_index)
            if canonical_bytes(value) != raw_index:
                raise ValueError("noncanonical index")
            reference = ArtifactRef.model_validate(value)
            if (
                reference.role != _ROLE_FOR_KIND[kind]
                or reference.media_type != _MEDIA_FOR_KIND[kind]
                or reference.size_bytes > self._max
            ):
                raise ValueError("index metadata mismatch")
            data = self._store.read_bytes(reference)
            if canonical_bytes(_strict_loads(data)) != data:
                raise ValueError("noncanonical record")
            record = model.model_validate(_strict_loads(data))
            if canonical_bytes(record) != data:
                raise ValueError("record model is not canonical")
        except Exception as exc:
            raise MainGraduationOfflineDrillJournalError(
                f"malformed or unverifiable C7 {kind}"
            ) from exc
        return record, reference

    @staticmethod
    def _parse(model: type[Any], value: Any, kind: str) -> Any:
        try:
            if not isinstance(value, model):
                value = model.model_validate(value)
            # Even a model instance is re-parsed to ensure subclasses and
            # model_construct values cannot bypass strict contract validation.
            return model.model_validate(value.model_dump(mode="json"))
        except Exception as exc:
            raise MainGraduationOfflineDrillJournalError(f"invalid C7 {kind}") from exc

    @staticmethod
    def _bind_case_to_plan(
        case: MainGraduationOfflineDrillCaseResult, plan: MainGraduationOfflineDrillPlan
    ) -> None:
        if (
            case.root_operation_id != plan.operation_id
            or case.plan_digest != plan.plan_digest
            or case.main_before_commit != plan.main_before_commit
            or case.main_before_tree != plan.main_before_tree
            or case.main_before_parents != plan.main_before_parents
            or case.operation_id
            != offline_drill_operation_id(plan.operation_id, case.case_id, case.vector_id)
        ):
            raise MainGraduationOfflineDrillJournalError(
                "case is not exactly bound to durable plan"
            )
        spec = next((item for item in plan.cases if item.case_id == case.case_id), None)
        if spec is None or case.vector_id not in {item.vector_id for item in spec.vectors}:
            raise MainGraduationOfflineDrillJournalError("case is outside frozen plan matrix")
        vector = next(item for item in spec.vectors if item.vector_id == case.vector_id)
        if (
            case.expected_outcome != vector.expected_outcome
            or case.expected_state != vector.expected_state
            or case.injected_fault_digest != vector.fault_digest
        ):
            raise MainGraduationOfflineDrillJournalError(
                "case expectation differs from durable plan"
            )

    @staticmethod
    def _bind_result_to_plan(
        result: MainGraduationOfflineDrillResult, plan: MainGraduationOfflineDrillPlan
    ) -> None:
        if (
            result.operation_id != plan.operation_id
            or result.plan_digest != plan.plan_digest
            or result.repository_digest != plan.repository_digest
            or result.target_ref != plan.target_ref
            or result.main_before_commit != plan.main_before_commit
            or result.main_before_tree != plan.main_before_tree
            or result.main_before_parents != plan.main_before_parents
            or result.main_after_commit != plan.main_before_commit
            or result.main_after_tree != plan.main_before_tree
            or result.main_after_parents != plan.main_before_parents
        ):
            raise MainGraduationOfflineDrillJournalError(
                "aggregate is not exactly bound to durable plan"
            )

    def _verify(self, kind: str, *args: Any) -> None:
        if self._verifier is None:
            raise MainGraduationOfflineDrillJournalError(
                "injected C7 authority verifier is required"
            )
        names = {"plan": "verify_plan", "case": "verify_case_result", "result": "verify_result"}
        method_name = names[kind]
        method = getattr(self._verifier, method_name, None)
        if method is None or not callable(method):
            raise MainGraduationOfflineDrillJournalError(
                f"injected C7 authority verifier is missing {method_name}"
            )
        try:
            signature = inspect.signature(method)
            signature.bind(*args)
            # A varargs method is not an exact protocol implementation.
            if any(
                parameter.kind is inspect.Parameter.VAR_POSITIONAL
                for parameter in signature.parameters.values()
            ):
                raise TypeError("variadic verifier signature")
            value = method(*args)
            if value is not True:
                raise ValueError("authority verifier did not return literal True")
        except Exception as exc:
            if isinstance(exc, MainGraduationOfflineDrillJournalError):
                raise
            raise MainGraduationOfflineDrillJournalError(
                f"C7 authority verifier rejected {kind}"
            ) from exc


def _strict_loads(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _binding(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract the required strict C7 envelope from an evidence object."""

    value = payload.get("c7_binding", payload)
    if not isinstance(value, dict):
        raise MainGraduationOfflineDrillJournalError("evidence has no typed C7 binding")
    return value


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {
            errno.EINVAL,
            errno.EACCES,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# Compatibility aliases follow the existing adapter naming convention.
OfflineDrillJournal = MainGraduationOfflineDrillJournal
OfflineDrillJournalError = MainGraduationOfflineDrillJournalError
OfflineDrillRecordConflictError = MainGraduationOfflineDrillRecordConflictError

__all__ = [
    "MainGraduationOfflineDrillAuthorityVerifier",
    "MainGraduationOfflineDrillJournal",
    "MainGraduationOfflineDrillJournalError",
    "MainGraduationOfflineDrillRecordConflictError",
    "MainGraduationOfflineDrillVerifier",
    "OfflineDrillAuthorityVerifier",
    "OfflineDrillJournal",
    "OfflineDrillJournalError",
    "OfflineDrillRecordConflictError",
]
