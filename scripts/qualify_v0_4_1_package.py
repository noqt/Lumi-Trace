# SPDX-License-Identifier: Apache-2.0
"""Build, reproduce, inspect, and installed-test V0.4.1 packages."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from lumi_trace.canonical import dump_json, load_json, sha256_file, stable_id
from lumi_trace.learned_ranker import LEARNED_RANKER, verify_model_artifact

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TIMESTAMP = "2026-07-26T00:00:00Z"
SOURCE_DATE_EPOCH = "1784995200"
STARTING_REVISION = "c93d3c792190435cb82e28f01af532be97d9a06a"


def _source_state_id() -> str:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    members = []
    for relative in sorted(completed.stdout.splitlines()):
        normalized = relative.replace("\\", "/")
        if normalized.startswith("evidence/v0.4.1/"):
            continue
        path = PROJECT_ROOT / relative
        if path.is_file():
            members.append(
                {
                    "path": normalized,
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    return stable_id(
        "lumi-trace-v0.4.1-source-state",
        {
            "starting_revision": STARTING_REVISION,
            "members": members,
        },
    )


def _root(path: Path, drive: str, *, create: bool = False) -> Path:
    resolved = path.resolve(strict=not create)
    if resolved.drive.casefold() != drive.casefold():
        raise ValueError(f"governed root must remain on {drive}")
    if create:
        resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise ValueError("governed root is not a directory")
    return resolved


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _normalize_source_distribution(path: Path, source_epoch: int) -> None:
    """Rewrite an sdist with canonical bounded TAR and gzip metadata."""

    records: list[tuple[str, bool, bool, bytes]] = []
    names: set[str] = set()
    total_bytes = 0
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 2_000:
            raise ValueError("source distribution exceeds the member limit")
        for member in members:
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or "\\" in member.name
                or pure.as_posix() != member.name
                or member.name in names
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("source distribution contains an unsafe member")
            names.add(member.name)
            content = b""
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError("source distribution file cannot be read")
                content = extracted.read()
                total_bytes += len(content)
                if total_bytes > 256 * 1024 * 1024:
                    raise ValueError("source distribution exceeds the byte limit")
            records.append((member.name, member.isdir(), bool(member.mode & 0o111), content))

    temporary = path.with_name(f".{path.name}.normalized.tmp")
    if temporary.exists():
        raise ValueError("source-distribution normalization target already exists")
    try:
        with (
            temporary.open("wb") as raw,
            gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=raw,
                compresslevel=9,
                mtime=source_epoch,
            ) as compressed,
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output,
        ):
            for name, is_directory, executable, content in sorted(records):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
                member.mode = 0o755 if is_directory or executable else 0o644
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.mtime = source_epoch
                member.size = 0 if is_directory else len(content)
                output.addfile(member, None if is_directory else io.BytesIO(content))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _build(output: Path, environment: dict[str, str]) -> tuple[Path, Path]:
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        environment=environment,
    )
    wheels = list(output.glob("*.whl"))
    sources = list(output.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("package build did not produce exactly one wheel and sdist")
    _normalize_source_distribution(sources[0], int(SOURCE_DATE_EPOCH))
    return wheels[0], sources[0]


def _inspect(wheel: Path, source: Path, model: dict) -> dict:
    forbidden_model_token = model["artifact_id"].split(":", 1)[1][:24]
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = sorted(archive.namelist())
        wheel_payloads = [
            archive.read(name)
            for name in wheel_members
            if not name.endswith("/") and archive.getinfo(name).file_size <= 2 * 1024 * 1024
        ]
    with tarfile.open(source, mode="r:gz") as archive:
        source_entries = archive.getmembers()
        source_members = sorted(member.name for member in source_entries)
        source_payloads = []
        for member in source_entries:
            if not member.isfile() or member.size > 2 * 1024 * 1024:
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                source_payloads.append(extracted.read())
    for members in (wheel_members, source_members):
        lowered = [item.casefold() for item in members]
        if (
            any("/evidence/" in f"/{item}/" for item in lowered)
            or any(forbidden_model_token in item for item in lowered)
            or any(item.endswith((".pt", ".pth", ".safetensors", ".onnx")) for item in lowered)
        ):
            raise ValueError("package contains evidence or a private weight artifact")
    model_signature = re.compile(
        rb'"schema_version"\s*:\s*"lumi-trace-localization-linear-ranker-v0\.4\.1"'
    )
    if any(
        model_signature.search(payload) and re.search(rb'"weights"\s*:\s*\[', payload)
        for payload in [*wheel_payloads, *source_payloads]
    ):
        raise ValueError("package contains a serialized V0.4.1 model")
    for required in (
        "lumi_trace/builder.py",
        "lumi_trace/learned_ranker.py",
        "lumi_trace/localization.py",
        "localization-inference-request-v0.4.1.json",
        "localization-linear-model-v0.4.1.json",
        "localization-raw-ranking-v0.4.1.json",
    ):
        if not any(item.endswith(required) for item in wheel_members):
            raise ValueError(f"wheel is missing V0.4.1 runtime member: {required}")
    return {
        "wheel_member_count": len(wheel_members),
        "source_member_count": len(source_members),
        "evidence_included": False,
        "private_model_included": False,
        "serialized_model_content_included": False,
        "runtime_and_schemas_included": True,
    }


def _record_predecessor_reproducibility_failure(
    package_root: Path,
    private_root: Path,
) -> str | None:
    candidates = []
    for directory in sorted(
        (item for item in package_root.iterdir() if item.is_dir()),
        key=lambda item: (item.stat().st_mtime_ns, item.name),
    ):
        wheels = list(directory.glob("*.whl"))
        sources = list(directory.glob("*.tar.gz"))
        if len(wheels) == 1 and len(sources) == 1:
            candidates.append((wheels[0], sources[0]))
    selected = None
    for index, first in enumerate(candidates):
        for second in candidates[index + 1 :]:
            if (
                first[0].read_bytes() == second[0].read_bytes()
                and first[1].read_bytes() != second[1].read_bytes()
            ):
                selected = (first, second)
                break
        if selected is not None:
            break
    if selected is None:
        return None
    first, second = selected
    record = {
        "schema_version": "lumi-trace-v0.4.1-package-attempt-disposition-v1",
        "state": "SUPERSEDED_FAILED_REPRODUCIBILITY_EVIDENCE",
        "reason": "UNNORMALIZED_GENERATED_SDIST_MTIMES",
        "wheel_byte_identical": True,
        "source_distribution_byte_identical": False,
        "first": {
            "wheel_sha256": sha256_file(first[0]),
            "source_distribution_sha256": sha256_file(first[1]),
        },
        "second": {
            "wheel_sha256": sha256_file(second[0]),
            "source_distribution_sha256": sha256_file(second[1]),
        },
        "deleted": False,
    }
    record["record_id"] = stable_id("v0.4.1-package-attempt-disposition", record)
    output = private_root / "invalidation" / "package-attempt-disposition.json"
    if output.exists():
        if load_json(output) != record:
            raise ValueError("append-only package failure disposition differs")
    else:
        dump_json(output, record)
    return record["record_id"]


def _installed_replay(
    *,
    wheel: Path,
    install_root: Path,
    work_root: Path,
    model_path: Path,
    environment: dict[str, str],
) -> dict:
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(install_root),
            str(wheel),
        ],
        cwd=work_root,
        environment=environment,
    )
    installed_env = {
        **environment,
        "PYTHONPATH": str(install_root),
        "PYTHONNOUSERSITE": "1",
    }
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "localization-repository"
    manual = PROJECT_ROOT / "tests" / "data" / "manual-finding.json"
    normalized = work_root / "installed-normalized.json"
    _run(
        [
            sys.executable,
            "-m",
            "lumi_trace",
            "import-manual",
            str(manual),
            "--repository",
            str(fixture),
            "--output",
            str(normalized),
        ],
        cwd=work_root,
        environment=installed_env,
    )
    outputs = {}
    for route, extra in (
        ("deterministic", ["--ranker", "role-aware-sparse-v0.4.1.3"]),
        (
            "learned",
            ["--ranker", LEARNED_RANKER, "--model", str(model_path)],
        ),
    ):
        documents = []
        for replay in (1, 2):
            output = work_root / f"installed-{route}-{replay}.json"
            _run(
                [
                    sys.executable,
                    "-m",
                    "lumi_trace",
                    "localize",
                    "--finding",
                    str(normalized),
                    "--repository",
                    str(fixture),
                    "--output",
                    str(output),
                    "--top-k",
                    "100",
                    *extra,
                ],
                cwd=work_root,
                environment=installed_env,
            )
            _run(
                [
                    sys.executable,
                    "-m",
                    "lumi_trace",
                    "validate",
                    str(output),
                ],
                cwd=work_root,
                environment=installed_env,
            )
            documents.append(load_json(output))
        deterministic_fields = (
            "request_id",
            "repository",
            "quarantine_policy",
            "candidate_algorithm",
            "ranker",
            "model_artifact_id",
            "generation",
            "candidate_count_ranked",
            "candidate_inventory",
            "candidates",
            "abstention",
            "ranking_id",
        )
        if any(documents[0][key] != documents[1][key] for key in deterministic_fields):
            raise ValueError(f"installed {route} replay differs")
        if not documents[0]["candidates"]:
            raise ValueError(f"installed {route} replay did not exercise candidate ranking")
        has_learned_components = all(
            {
                "LEARNED_INTEGER_LINEAR",
                "LEARNED_HYBRID_CONTRIBUTION",
            }
            <= candidate["score_components"].keys()
            for candidate in documents[0]["candidates"]
        )
        if (route == "learned") != has_learned_components:
            raise ValueError(f"installed {route} replay exercised the wrong ranker")
        nonzero_learned_contribution = any(
            candidate["score_components"].get("LEARNED_HYBRID_CONTRIBUTION", 0) != 0
            for candidate in documents[0]["candidates"]
        )
        if route == "learned" and not nonzero_learned_contribution:
            raise ValueError("installed learned replay produced no learned contribution")
        if (route == "learned") != (documents[0]["model_artifact_id"] is not None):
            raise ValueError(f"installed {route} replay has the wrong model binding")
        network_used = any(item["telemetry"]["network_used"] is True for item in documents)
        repository_code_executed = any(
            item["telemetry"]["repository_code_executed"] is True for item in documents
        )
        if network_used or repository_code_executed:
            raise ValueError(f"installed {route} replay violated its execution boundary")
        outputs[route] = {
            "ranking_id": documents[0]["ranking_id"],
            "raw_output_seal": documents[0]["raw_output_seal"],
            "candidate_count": len(documents[0]["candidates"]),
            "nonzero_learned_contribution": nonzero_learned_contribution,
            "deterministic_projection_exact": True,
            "maximum_wall_seconds": max(item["telemetry"]["wall_seconds"] for item in documents),
            "maximum_cpu_seconds": max(item["telemetry"]["cpu_seconds"] for item in documents),
            "maximum_peak_python_bytes": max(
                item["telemetry"]["peak_python_bytes"] or 0 for item in documents
            ),
            "network_used": network_used,
            "repository_code_executed": repository_code_executed,
        }
    if outputs["deterministic"]["raw_output_seal"] == outputs["learned"]["raw_output_seal"]:
        raise ValueError("installed learned route is indistinguishable from deterministic")
    return outputs


def qualify(args: argparse.Namespace) -> dict:
    private_root = _root(args.private_root, "G:")
    work_root = _root(args.work_root, "F:")
    model_path = args.model.resolve(strict=True)
    if model_path.drive.casefold() != "f:" or work_root not in model_path.parents:
        raise ValueError("package-test model must remain under the F: work root")
    model = verify_model_artifact(load_json(model_path))
    source_state_id = _source_state_id()
    superseded_package_record = None
    predecessor_package_path = private_root / "manifests" / "package-qualification.json"
    if predecessor_package_path.is_file():
        predecessor_package = load_json(predecessor_package_path)
        candidate_counts = {
            route: predecessor_package.get("installed_replay", {})
            .get(route, {})
            .get("candidate_count")
            for route in ("deterministic", "learned")
        }
        if candidate_counts != {"deterministic": 0, "learned": 0}:
            raise ValueError("predecessor package record has an unexpected disposition")
        superseded_package_record = {
            "schema_version": "lumi-trace-v0.4.1-package-record-disposition-v1",
            "predecessor_record_id": predecessor_package["record_id"],
            "state": "SUPERSEDED_INVALID_ZERO_CANDIDATE_REPLAY",
            "candidate_counts": candidate_counts,
            "reason": "SHELL_ONLY_FIXTURE_DID_NOT_EXERCISE_LOCALIZATION_RANKERS",
            "deleted": False,
        }
        superseded_package_record["record_id"] = stable_id(
            "v0.4.1-package-record-disposition",
            superseded_package_record,
        )
        disposition_path = (
            private_root / "invalidation" / "package-qualification-record-disposition.json"
        )
        if disposition_path.exists():
            if load_json(disposition_path) != superseded_package_record:
                raise ValueError("append-only package record disposition differs")
        else:
            dump_json(disposition_path, superseded_package_record)
    package_root = work_root / "package-qualification"
    package_root.mkdir(parents=True, exist_ok=True)
    failed_attempt_id = _record_predecessor_reproducibility_failure(
        package_root,
        private_root,
    )
    first_root = Path(tempfile.mkdtemp(prefix="build-a-", dir=package_root))
    second_root = Path(tempfile.mkdtemp(prefix="build-b-", dir=package_root))
    environment = {
        **os.environ,
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        "TEMP": str(package_root),
        "TMP": str(package_root),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }
    first_wheel, first_source = _build(first_root, environment)
    second_wheel, second_source = _build(second_root, environment)
    if (
        first_wheel.read_bytes() != second_wheel.read_bytes()
        or first_source.read_bytes() != second_source.read_bytes()
    ):
        raise ValueError("two clean package builds are not byte-identical")
    inspection = _inspect(first_wheel, first_source, model)
    _run(
        [sys.executable, "-m", "twine", "check", str(first_wheel), str(first_source)],
        cwd=work_root,
        environment=environment,
    )
    install_root = Path(tempfile.mkdtemp(prefix="installed-", dir=package_root))
    installed = _installed_replay(
        wheel=first_wheel,
        install_root=install_root,
        work_root=package_root,
        model_path=model_path,
        environment=environment,
    )
    record = {
        "schema_version": "lumi-trace-v0.4.1-private-package-qualification-v1",
        "model_artifact_id": model["artifact_id"],
        "source_state_id": source_state_id,
        "predecessor_failed_attempt_id": failed_attempt_id,
        "superseded_package_record_id": (
            None if superseded_package_record is None else superseded_package_record["record_id"]
        ),
        "source_date_epoch": int(SOURCE_DATE_EPOCH),
        "wheel": {
            "filename": first_wheel.name,
            "sha256": sha256_file(first_wheel),
            "size_bytes": first_wheel.stat().st_size,
        },
        "source_distribution": {
            "filename": first_source.name,
            "sha256": sha256_file(first_source),
            "size_bytes": first_source.stat().st_size,
        },
        "two_clean_builds_byte_identical": True,
        "twine_check": "PASS",
        "inspection": inspection,
        "installed_replay": installed,
        "external_dependencies_installed": False,
        "model_packaged": False,
        "qualification_authorised": False,
        "created_at": TIMESTAMP,
    }
    if _source_state_id() != source_state_id:
        raise ValueError("source state changed during package qualification")
    record["record_id"] = stable_id("v0.4.1-package-qualification", record)
    output = private_root / "manifests" / "package-qualification-final.json"
    if output.exists() and load_json(output) != record:
        raise ValueError("append-only package qualification record differs")
    dump_json(output, record)
    return record


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--model", type=Path, required=True)
    result.add_argument(
        "--private-root",
        type=Path,
        default=Path("G:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    result.add_argument(
        "--work-root",
        type=Path,
        default=Path("F:/Data/skylark-lumi-trace-eval/v0.4.1"),
    )
    return result


def main() -> int:
    try:
        record = qualify(parser().parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"qualify-v0.4.1-package: {exc}", file=sys.stderr)
        return 2
    print(record["record_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
