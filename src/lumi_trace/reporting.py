# SPDX-License-Identifier: Apache-2.0
"""Evidence classification, bundle construction, and SARIF 2.1.0 export."""

from __future__ import annotations

import platform
import re
from typing import Any

from . import __version__
from .canonical import stable_id
from .errors import IntegrityError
from .findings import validate_normalized_finding
from .indexing import (
    INDEX_ALGORITHM,
    LEGACY_INDEX_ALGORITHM,
    SUPPORTED_INDEX_ALGORITHMS,
    verify_repository_identity,
)
from .localization import (
    CANDIDATE_TRUNCATION_ABSTENTION,
    NO_SIGNAL_ABSTENTION,
    V041_EVIDENCE_CANDIDATE_ALGORITHM,
)
from .ranking import (
    PRODUCT_CANDIDATE_ALGORITHM,
    PRODUCT_RANKING_ALGORITHM,
    PRODUCT_ROLES,
    RANKING_ALGORITHM,
    verify_ranked_candidates,
)
from .sandbox import verify_reproduction_receipt

_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_INDEX_BY_PRODUCT_CANDIDATE_ALGORITHM = {
    V041_EVIDENCE_CANDIDATE_ALGORITHM: LEGACY_INDEX_ALGORITHM,
    PRODUCT_CANDIDATE_ALGORITHM: INDEX_ALGORITHM,
}


def classify_evidence(
    *, reproduction_requested: bool, receipt: dict[str, Any] | None
) -> dict[str, object]:
    """Apply fail-closed product classifications to a reproduction receipt."""

    if not reproduction_requested:
        return {
            "outcome": "INSUFFICIENT_EVIDENCE",
            "reason_codes": ["NO_REPRODUCTION_PLAN"],
            "confidence_grade": "D",
            "confidence_basis_points": 2500,
            "confidence_is_not_probability": True,
        }
    if receipt is None:
        return {
            "outcome": "INSUFFICIENT_EVIDENCE",
            "reason_codes": ["NO_REPRODUCTION_RECEIPT"],
            "confidence_grade": "D",
            "confidence_basis_points": 2000,
            "confidence_is_not_probability": True,
        }

    status = str(receipt.get("status", "UNKNOWN"))
    if status == "UNSUPPORTED":
        reasons = receipt.get("reason_codes") or ["REPRODUCTION_UNSUPPORTED"]
        return {
            "outcome": "UNSUPPORTED",
            "reason_codes": sorted(set(map(str, reasons))),
            "confidence_grade": "A",
            "confidence_basis_points": 9500,
            "confidence_is_not_probability": True,
        }

    sandbox = receipt.get("sandbox") if isinstance(receipt.get("sandbox"), dict) else {}
    qualification = (
        receipt.get("qualification") if isinstance(receipt.get("qualification"), dict) else {}
    )
    repository = receipt.get("repository") if isinstance(receipt.get("repository"), dict) else {}
    steps = receipt.get("steps") if isinstance(receipt.get("steps"), list) else []
    reasons: list[str] = []
    receipt_reason_codes = receipt.get("reason_codes")
    if (
        not isinstance(receipt_reason_codes, list)
        or not receipt_reason_codes
        or not all(
            isinstance(code, str) and _REASON_CODE.fullmatch(code) for code in receipt_reason_codes
        )
        or len(receipt_reason_codes) != len(set(receipt_reason_codes))
    ):
        reasons.append("RECEIPT_REASON_CODES_INVALID")
    elif status == "COMPLETED":
        unexpected = set(receipt_reason_codes) - {"EXECUTION_COMPLETED"}
        reasons.extend(sorted(unexpected))
        if "EXECUTION_COMPLETED" not in receipt_reason_codes:
            reasons.append("EXECUTION_COMPLETION_NOT_ATTESTED")
    if receipt.get("attempted") is not True:
        reasons.append("REPRODUCTION_NOT_ATTEMPTED")
    if not sandbox.get("qualified"):
        reasons.append("SANDBOX_NOT_QUALIFIED")
    if sandbox.get("network_mode") != "none":
        reasons.append("NETWORK_DENIAL_NOT_ATTESTED")
    if sandbox.get("backend") != "docker":
        reasons.append("SANDBOX_BACKEND_NOT_ATTESTED")
    if sandbox.get("source_mount") != "read_only":
        reasons.append("READ_ONLY_SOURCE_NOT_ATTESTED")
    qualification_flags = (
        "qualified",
        "container_policy_verified",
        "non_root",
        "no_default_ipv4_route",
        "no_default_ipv6_route",
        "engine_sockets_absent",
        "host_credential_mounts_absent",
        "credential_environment_absent",
        "core_dumps_disabled",
        "source_read_only",
    )
    if (
        any(qualification.get(key) is not True for key in qualification_flags)
        or qualification.get("uid") != 65_532
    ):
        reasons.append("SANDBOX_QUALIFICATION_NOT_ATTESTED")
    if qualification.get("image_id") != sandbox.get("image_id"):
        reasons.append("SANDBOX_IMAGE_IDENTITY_MISMATCH")
    if repository.get("unchanged") is not True:
        reasons.append("REPOSITORY_IMMUTABILITY_NOT_ATTESTED")
    if repository.get("before") != receipt.get("repository_identity") or repository.get(
        "after"
    ) != receipt.get("repository_identity"):
        reasons.append("REPOSITORY_IDENTITY_MISMATCH")
    if status == "TIMED_OUT":
        reasons.append("REPRODUCTION_TIMEOUT")
    elif status == "OUTPUT_LIMIT":
        reasons.append("REPRODUCTION_OUTPUT_LIMIT")
    elif status != "COMPLETED":
        reasons.append("REPRODUCTION_INFRASTRUCTURE_FAILURE")
    if not steps:
        reasons.append("NO_REPRODUCTION_STEPS")
    if any(
        not isinstance(step, dict)
        or step.get("termination_reason") != "completed"
        or step.get("timed_out") is not False
        or step.get("output_limit_exceeded") is not False
        or step.get("oom_killed") is not False
        for step in steps
    ):
        reasons.append("STEP_COMPLETION_NOT_ATTESTED")
    witnesses = [
        step.get("witness", {})
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("witness"), dict)
    ]
    witness_results = [witness.get("matched") is True for witness in witnesses]
    witness_consistency = []
    for witness in witnesses:
        predicates = [
            witness.get(key)
            for key in ("exit_code", "stdout_contains", "stderr_contains")
            if witness.get(key) is not None
        ]
        witness_consistency.append(
            bool(predicates)
            and all(isinstance(item, bool) for item in predicates)
            and witness.get("matched") == all(predicates)
        )
    if not witness_consistency or not all(witness_consistency):
        reasons.append("WITNESS_ATTESTATION_INCONSISTENT")
    if not witness_results or not all(witness_results):
        reasons.append("EXPLICIT_WITNESS_NOT_OBSERVED")
    runtime = receipt.get("runtime") if isinstance(receipt.get("runtime"), dict) else {}
    cleanup = runtime.get("step_cleanup") if isinstance(runtime.get("step_cleanup"), list) else []
    if runtime.get("qualification_cleanup_verified") is not True or len(cleanup) != len(steps):
        reasons.append("SANDBOX_CLEANUP_NOT_ATTESTED")
    if runtime.get("engine_endpoint_class") not in {
        "local-unix-socket",
        "local-windows-named-pipe",
    }:
        reasons.append("LOCAL_ENGINE_ENDPOINT_NOT_ATTESTED")
    elif any(
        not isinstance(item, dict) or item.get("remove_succeeded") is not True for item in cleanup
    ):
        reasons.append("SANDBOX_CLEANUP_NOT_ATTESTED")

    if not reasons:
        return {
            "outcome": "CONFIRMED",
            "reason_codes": ["QUALIFIED_SANDBOX_EXPLICIT_WITNESS"],
            "confidence_grade": "A",
            "confidence_basis_points": 9500,
            "confidence_is_not_probability": True,
        }
    return {
        "outcome": "INSUFFICIENT_EVIDENCE",
        "reason_codes": sorted(set(reasons)),
        "confidence_grade": "C" if status == "COMPLETED" else "D",
        "confidence_basis_points": 5000 if status == "COMPLETED" else 2000,
        "confidence_is_not_probability": True,
    }


def build_evidence_bundle(
    *,
    finding: dict[str, object],
    repository: dict[str, object],
    index: dict[str, object],
    candidate_set: dict[str, object],
    reproduction_requested: bool,
    receipt: dict[str, Any] | None,
    source_revision: str = "uncommitted",
) -> dict[str, object]:
    """Build the canonical public-safe evidence bundle."""

    classification = classify_evidence(
        reproduction_requested=reproduction_requested, receipt=receipt
    )
    reproduction: dict[str, object] = {
        "requested": reproduction_requested,
        "attempted": bool(receipt and receipt.get("attempted")),
        "receipts": [receipt] if receipt else [],
    }
    if receipt:
        for key in ("plan_id", "policy_id"):
            if key in receipt:
                reproduction[key] = receipt[key]
        sandbox = receipt.get("sandbox")
        if isinstance(sandbox, dict):
            reproduction["sandbox_qualified"] = bool(sandbox.get("qualified"))

    ranking = None
    if candidate_set.get("algorithm") == PRODUCT_RANKING_ALGORITHM:
        roles = sorted(
            {
                str(candidate["role"])
                for candidate in candidate_set["candidates"]  # type: ignore[index]
                if isinstance(candidate, dict)
            }
        )
        ranking = {
            "ranker": candidate_set["algorithm"],
            "candidate_algorithm": candidate_set["candidate_algorithm"],
            "ranking_id": candidate_set["ranking_id"],
            "candidate_count_considered": candidate_set["candidate_count_considered"],
            "candidates_emitted": len(candidate_set["candidates"]),  # type: ignore[arg-type]
            "score_basis": "DETERMINISTIC_INTEGER_COMPONENTS_WITH_ROLE_PRIORS",
            "roles_emitted": roles,
            "abstention": candidate_set["abstention"],
            "confidence_descriptor": candidate_set["confidence_descriptor"],
            "confidence_is_not_probability": True,
        }

    payload: dict[str, object] = {
        "schema_version": "evidence-bundle-v1",
        "tool": {
            "name": "Lumi Trace",
            "version": __version__,
            "source_revision": source_revision,
            "model_provider": None,
            "checkpoint": None,
            "current_weights": 0,
        },
        "finding": finding,
        "repository": repository,
        "index": {
            "index_id": index["index_id"],
            "algorithm": index["algorithm"],
            "file_count": index["file_count"],
            "indexed_text_file_count": index["indexed_text_file_count"],
            "symbol_count": index["symbol_count"],
            "exclusions": index["exclusions"],
        },
        "candidates": candidate_set["candidates"],
        "reproduction": reproduction,
        "classification": classification,
        "provenance": {
            "finding_input_sha256": finding["source"]["input_sha256"],  # type: ignore[index]
            "repository_manifest_id": repository["manifest_id"],
            "index_id": index["index_id"],
            "candidate_set_id": candidate_set["candidate_set_id"],
            "schema_versions": [
                "normalized-finding-v1",
                "repository-index-v1",
                "candidate-set-v1",
                "evidence-bundle-v1",
            ],
            "runtime": {
                "python": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform_system": platform.system(),
            },
            "environment_key_names": [],
            "external_network_calls": 0,
        },
        "telemetry": {
            "repository_files": repository["file_count"],
            "repository_bytes": repository["total_bytes"],
            "text_files_indexed": index["indexed_text_file_count"],
            "symbols_indexed": index["symbol_count"],
            "candidates_considered": candidate_set["candidate_count_considered"],
            "candidates_emitted": len(candidate_set["candidates"]),
            "reproduction_steps": len(receipt.get("steps", [])) if receipt else 0,
        },
        "limitations": [
            "Candidate scores are deterministic retrieval heuristics, not probabilities.",
            (
                "Step 1 implementation-location ranking considers Python files and symbols only."
                if ranking is not None
                else "Non-Python symbol extraction is lexical and may be incomplete."
            ),
            "CONFIRMED applies only to the declared reproduction witness in the supplied snapshot.",
            "No learned model, checkpoint, hosted inference, or repair generation is used.",
        ],
    }
    if ranking is not None:
        payload["ranking"] = ranking
    payload["bundle_id"] = stable_id("evidence-bundle", payload)
    return payload


def verify_evidence_bundle(bundle: dict[str, object]) -> None:
    """Verify bundle identity, zero-model boundary, and embedded evidence semantics."""

    required = {
        "schema_version",
        "tool",
        "finding",
        "repository",
        "index",
        "candidates",
        "reproduction",
        "classification",
        "provenance",
        "telemetry",
        "limitations",
        "bundle_id",
    }
    optional = {"ranking"}
    if (
        not isinstance(bundle, dict)
        or not required.issubset(bundle)
        or set(bundle) - required - optional
    ):
        raise IntegrityError("evidence bundle fields do not match evidence-bundle-v1")
    if bundle.get("schema_version") != "evidence-bundle-v1":
        raise IntegrityError("not an evidence-bundle-v1 document")
    finding = bundle.get("finding")
    if not isinstance(finding, dict):
        raise IntegrityError("evidence bundle finding is invalid")
    validate_normalized_finding(finding)
    tool = bundle.get("tool") if isinstance(bundle.get("tool"), dict) else {}
    if (
        set(tool)
        != {
            "name",
            "version",
            "source_revision",
            "model_provider",
            "checkpoint",
            "current_weights",
        }
        or tool.get("name") != "Lumi Trace"
        or tool.get("version") != __version__
        or not isinstance(tool.get("source_revision"), str)
        or not tool["source_revision"]
        or len(tool["source_revision"]) > 256
        or "\x00" in tool["source_revision"]
        or tool.get("model_provider") is not None
        or tool.get("checkpoint") is not None
        or tool.get("current_weights") != 0
    ):
        raise IntegrityError("evidence bundle violates the zero-model V0.1 boundary")
    repository = bundle.get("repository")
    if not isinstance(repository, dict):
        raise IntegrityError("evidence bundle repository identity is invalid")
    verify_repository_identity(repository)
    index = bundle.get("index") if isinstance(bundle.get("index"), dict) else {}
    if (
        set(index)
        != {
            "index_id",
            "algorithm",
            "file_count",
            "indexed_text_file_count",
            "symbol_count",
            "exclusions",
        }
        or not isinstance(index.get("index_id"), str)
        or re.fullmatch(r"index:[0-9a-f]{64}", index["index_id"]) is None
        or index.get("algorithm") not in SUPPORTED_INDEX_ALGORITHMS
        or any(
            not _nonnegative_integer(index.get(key))
            for key in ("file_count", "indexed_text_file_count", "symbol_count")
        )
        or index.get("file_count") != repository.get("file_count")
        or index.get("indexed_text_file_count") > index.get("file_count")
    ):
        raise IntegrityError("evidence bundle index summary is invalid")
    exclusions = index.get("exclusions")
    if (
        not isinstance(exclusions, dict)
        or set(exclusions) - {"oversized", "binary", "unsupported_encoding"}
        or any(not _nonnegative_integer(value) for value in exclusions.values())
    ):
        raise IntegrityError("evidence bundle index exclusions are invalid")
    ranking = bundle.get("ranking")
    verify_ranked_candidates(bundle.get("candidates"), require_role=ranking is not None)
    if ranking is not None:
        candidates = bundle["candidates"]
        if not isinstance(ranking, dict) or set(ranking) != {
            "ranker",
            "candidate_algorithm",
            "ranking_id",
            "candidate_count_considered",
            "candidates_emitted",
            "score_basis",
            "roles_emitted",
            "abstention",
            "confidence_descriptor",
            "confidence_is_not_probability",
        }:
            raise IntegrityError("evidence bundle ranking summary is invalid")
        abstention = ranking.get("abstention")
        expected_roles = sorted(
            {str(candidate["role"]) for candidate in candidates if isinstance(candidate, dict)}
        )
        if (
            ranking.get("ranker") != PRODUCT_RANKING_ALGORITHM
            or ranking.get("candidate_algorithm") not in _INDEX_BY_PRODUCT_CANDIDATE_ALGORITHM
            or _INDEX_BY_PRODUCT_CANDIDATE_ALGORITHM.get(str(ranking.get("candidate_algorithm")))
            != index.get("algorithm")
            or ranking.get("score_basis") != "DETERMINISTIC_INTEGER_COMPONENTS_WITH_ROLE_PRIORS"
            or ranking.get("roles_emitted") != expected_roles
            or any(role not in PRODUCT_ROLES for role in expected_roles)
            or ranking.get("candidates_emitted") != len(candidates)
            or not _nonnegative_integer(ranking.get("candidate_count_considered"))
            or ranking["candidate_count_considered"] < len(candidates)
            or not isinstance(abstention, dict)
            or set(abstention) != {"abstained", "reason"}
            or not isinstance(abstention.get("abstained"), bool)
            or (
                abstention["abstained"]
                and abstention.get("reason")
                not in {NO_SIGNAL_ABSTENTION, CANDIDATE_TRUNCATION_ABSTENTION}
            )
            or (not abstention["abstained"] and abstention.get("reason") is not None)
            or (abstention["abstained"] and candidates)
            or (not abstention["abstained"] and not candidates)
            or ranking.get("confidence_descriptor")
            != ("ABSTAINED" if abstention.get("abstained") else "FINDING_GUIDED_SIGNAL_PRESENT")
            or ranking.get("confidence_is_not_probability") is not True
        ):
            raise IntegrityError("evidence bundle ranking summary is inconsistent")
        ranking_identity = {
            "algorithm": PRODUCT_RANKING_ALGORITHM,
            "candidate_algorithm": ranking["candidate_algorithm"],
            "finding_id": finding["finding_id"],
            "index_id": index["index_id"],
            "candidate_ids": [candidate["candidate_id"] for candidate in candidates],
            "abstention": abstention,
        }
        if ranking.get("ranking_id") != stable_id("ranking", ranking_identity):
            raise IntegrityError("evidence bundle ranking identity is invalid")
    reproduction = (
        bundle.get("reproduction") if isinstance(bundle.get("reproduction"), dict) else None
    )
    reproduction_base = {"requested", "attempted", "receipts"}
    reproduction_optional = {"plan_id", "policy_id", "sandbox_qualified"}
    if (
        reproduction is None
        or not reproduction_base.issubset(reproduction)
        or set(reproduction) - reproduction_base - reproduction_optional
        or not isinstance(reproduction.get("requested"), bool)
        or not isinstance(reproduction.get("attempted"), bool)
    ):
        raise IntegrityError("evidence bundle reproduction state is invalid")
    receipts = reproduction.get("receipts")
    if not isinstance(receipts, list) or len(receipts) > 1:
        raise IntegrityError("evidence bundle receipt collection is invalid")
    receipt = receipts[0] if receipts else None
    if receipt is not None:
        if not isinstance(receipt, dict):
            raise IntegrityError("evidence bundle receipt is invalid")
        verify_reproduction_receipt(receipt)
        if receipt.get("repository_identity") != repository.get("repository_id"):
            raise IntegrityError("evidence bundle receipt repository identity mismatch")
        if (
            set(reproduction) != reproduction_base | reproduction_optional
            or reproduction.get("plan_id") != receipt.get("plan_id")
            or reproduction.get("policy_id") != receipt.get("policy_id")
            or reproduction.get("sandbox_qualified")
            is not bool(receipt.get("sandbox", {}).get("qualified"))
            or reproduction.get("attempted") is not receipt.get("attempted")
        ):
            raise IntegrityError("evidence bundle receipt provenance mismatch")
    elif set(reproduction) != reproduction_base or reproduction.get("attempted") is not False:
        raise IntegrityError("evidence bundle empty reproduction state is inconsistent")
    provenance = bundle.get("provenance") if isinstance(bundle.get("provenance"), dict) else {}
    if set(provenance) != {
        "finding_input_sha256",
        "repository_manifest_id",
        "index_id",
        "candidate_set_id",
        "schema_versions",
        "runtime",
        "environment_key_names",
        "external_network_calls",
    }:
        raise IntegrityError("evidence bundle provenance structure is invalid")
    runtime = provenance.get("runtime") if isinstance(provenance.get("runtime"), dict) else {}
    environment_names = provenance.get("environment_key_names")
    if (
        provenance.get("finding_input_sha256") != finding.get("source", {}).get("input_sha256")
        or provenance.get("repository_manifest_id") != repository.get("manifest_id")
        or provenance.get("index_id") != index.get("index_id")
        or not isinstance(provenance.get("candidate_set_id"), str)
        or re.fullmatch(r"candidate-set:[0-9a-f]{64}", provenance["candidate_set_id"]) is None
        or provenance.get("schema_versions")
        != [
            "normalized-finding-v1",
            "repository-index-v1",
            "candidate-set-v1",
            "evidence-bundle-v1",
        ]
        or set(runtime) != {"python", "implementation", "platform_system"}
        or any(not isinstance(value, str) or not value for value in runtime.values())
        or not isinstance(environment_names, list)
        or any(
            not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
            for name in environment_names
        )
        or len(environment_names) != len(set(environment_names))
        or provenance.get("external_network_calls") != 0
    ):
        raise IntegrityError("evidence bundle provenance is invalid")
    telemetry = bundle.get("telemetry") if isinstance(bundle.get("telemetry"), dict) else {}
    telemetry_fields = {
        "repository_files",
        "repository_bytes",
        "text_files_indexed",
        "symbols_indexed",
        "candidates_considered",
        "candidates_emitted",
        "reproduction_steps",
    }
    candidates = bundle["candidates"]
    if (
        set(telemetry) != telemetry_fields
        or any(not _nonnegative_integer(value) for value in telemetry.values())
        or telemetry.get("repository_files") != repository.get("file_count")
        or telemetry.get("repository_bytes") != repository.get("total_bytes")
        or telemetry.get("text_files_indexed") != index.get("indexed_text_file_count")
        or telemetry.get("symbols_indexed") != index.get("symbol_count")
        or telemetry.get("candidates_emitted") != len(candidates)
        or telemetry.get("candidates_considered") < len(candidates)
        or (
            isinstance(ranking, dict)
            and (
                telemetry.get("candidates_considered") != ranking.get("candidate_count_considered")
                or telemetry.get("candidates_emitted") != ranking.get("candidates_emitted")
            )
        )
        or telemetry.get("reproduction_steps")
        != (len(receipt.get("steps", [])) if isinstance(receipt, dict) else 0)
    ):
        raise IntegrityError("evidence bundle telemetry is inconsistent")
    limitations = bundle.get("limitations")
    if (
        not isinstance(limitations, list)
        or not limitations
        or any(not isinstance(item, str) or not item or len(item) > 1_024 for item in limitations)
        or len(limitations) != len(set(limitations))
    ):
        raise IntegrityError("evidence bundle limitations are invalid")
    expected_classification = classify_evidence(
        reproduction_requested=reproduction["requested"], receipt=receipt
    )
    if bundle.get("classification") != expected_classification:
        raise IntegrityError("evidence bundle classification is inconsistent with its receipt")
    actual = bundle.get("bundle_id")
    expected = stable_id("evidence-bundle", bundle, omit_keys=("bundle_id",))
    if actual != expected:
        raise IntegrityError(f"bundle identity mismatch: expected {expected}, got {actual}")


def _nonnegative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _sarif_region(region: dict[str, Any]) -> dict[str, int]:
    return {
        "startLine": int(region["start_line"]),
        "startColumn": int(region.get("start_column", 1)),
        "endLine": int(region["end_line"]),
        "endColumn": int(region.get("end_column", 1)),
    }


def _sarif_location(candidate: dict[str, Any], *, identifier: int | None = None) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": candidate["path"], "uriBaseId": "%SRCROOT%"},
            "region": _sarif_region(candidate["region"]),
        },
        "properties": {
            "candidateId": candidate["candidate_id"],
            "rank": candidate["rank"],
            "integerScore": candidate["integer_score"],
            "scoreReasons": candidate["score_reasons"],
        },
    }
    role = candidate.get("role")
    if isinstance(role, str):
        location["properties"]["locationRole"] = role
    if identifier is not None:
        location["id"] = identifier
    symbol = candidate.get("symbol")
    if isinstance(symbol, dict):
        location["logicalLocations"] = [
            {
                "name": symbol.get("name"),
                "fullyQualifiedName": symbol.get("qualified_name"),
                "kind": symbol.get("kind"),
            }
        ]
    return location


def export_sarif(bundle: dict[str, object]) -> dict[str, object]:
    """Project an evidence bundle into SARIF 2.1.0 without source snippets."""

    verify_evidence_bundle(bundle)
    finding = bundle["finding"]
    rule = finding["rule"]
    classification = bundle["classification"]
    ranking = bundle.get("ranking")
    candidates = bundle.get("candidates", [])
    outcome = str(classification["outcome"])
    severity = str(finding["severity"]["normalized"])
    level_by_severity = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "warning",
        "NOTE": "note",
        "UNKNOWN": "none",
    }
    result: dict[str, object] = {
        "ruleId": rule["id"],
        "level": level_by_severity.get(severity, "none"),
        "kind": "fail" if outcome == "CONFIRMED" else "informational",
        "message": {"text": f"Lumi Trace classification: {outcome}. {finding['message']['title']}"},
        "properties": {
            "lumiTraceBundleId": bundle["bundle_id"],
            "classification": outcome,
            "reasonCodes": classification["reason_codes"],
            "confidenceGrade": classification["confidence_grade"],
            "confidenceBasisPoints": classification["confidence_basis_points"],
            "confidenceIsNotProbability": True,
            "rankingAlgorithm": (
                ranking["ranker"] if isinstance(ranking, dict) else RANKING_ALGORITHM
            ),
            "repositoryId": bundle["repository"]["repository_id"],
            "modelCheckpoint": None,
            "currentWeights": 0,
        },
        "fingerprints": finding.get("fingerprints", {}),
    }
    if isinstance(ranking, dict):
        result["properties"].update(
            {
                "candidateAlgorithm": ranking["candidate_algorithm"],
                "rankingId": ranking["ranking_id"],
                "rankingAbstained": ranking["abstention"]["abstained"],
                "rankingAbstentionReason": ranking["abstention"]["reason"],
                "rankingConfidenceDescriptor": ranking["confidence_descriptor"],
                "rankingConfidenceIsNotProbability": True,
                "rankedRoles": ranking["roles_emitted"],
            }
        )
    if candidates:
        result["locations"] = [_sarif_location(candidates[0])]
        result["relatedLocations"] = [
            _sarif_location(candidate, identifier=number)
            for number, candidate in enumerate(candidates[1:], start=1)
        ]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Lumi Trace",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/noqt/Lumi-Trace",
                        "rules": [
                            {
                                "id": rule["id"],
                                "name": rule["name"],
                                "shortDescription": {"text": finding["message"]["title"]},
                                "properties": {"tags": rule.get("tags", []) + rule.get("cwes", [])},
                            }
                        ],
                    }
                },
                "automationDetails": {"id": bundle["bundle_id"]},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
                "results": [result],
                "properties": {
                    "repositoryManifestId": bundle["repository"]["manifest_id"],
                    "externalNetworkCalls": 0,
                    "pythonVersion": bundle["provenance"]["runtime"]["python"],
                },
            }
        ],
    }
