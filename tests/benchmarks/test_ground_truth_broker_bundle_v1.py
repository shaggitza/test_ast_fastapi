from __future__ import annotations

import hashlib
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest
from benchmarks.real_world import ground_truth_broker_bundle_v1 as bundle_v1

if TYPE_CHECKING:
    from pathlib import Path


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def make_bundle(tmp_path: Path) -> bundle_v1.Bundle:
    source = tmp_path / "checkout"
    (source / "broker").mkdir(parents=True)
    (source / "broker/__init__.py").write_bytes(b"from .worker import serve\n")
    (source / "broker/worker.py").write_bytes(b"def serve(): return True\n")
    return bundle_v1.materialize_bundle(
        source,
        tmp_path / "sealed",
        ("broker/__init__.py", "broker/worker.py"),
        profile_sha256=digest(b"profile-v2"),
        toolchain_sha256=bundle_v1.compute_toolchain_sha256(()),
        entrypoint="broker/__init__.py",
    )


def receipt(bundle: bundle_v1.Bundle) -> bundle_v1.FreezeReceipt:
    return bundle_v1.FreezeReceipt.parse(
        {
            "schema_version": 1,
            "protocol": bundle_v1.RECEIPT_PROTOCOL,
            "runtime_attestation_path": "/tmp/runtime-attestation.json",
            "runtime_attestation_sha256": digest(b"runtime"),
            "bundle_manifest_path": str(bundle.root / "bundle-manifest-v1.json"),
            "bundle_sha256": bundle.digest,
            "binding_path": "/tmp/binding.json",
            "binding_sha256": digest(b"binding"),
            "launch_profile_path": "/tmp/launch-profile.json",
            "launch_profile_protocol": bundle_v1.LAUNCH_PROFILE_PROTOCOL,
            "launch_profile_sha256": bundle.profile_sha256,
            "toolchain_sha256": bundle.toolchain_sha256,
            "lease_path": "/tmp/lease.lock",
            "hold_until": "escrow_finalized",
        }
    )


def identities(
    bundle: bundle_v1.Bundle,
    *,
    runtime_sha256: str | None = None,
    binding_sha256: str | None = None,
    launch_profile_sha256: str | None = None,
) -> dict[str, str]:
    return {
        "runtime_attestation_sha256": runtime_sha256 or digest(b"runtime"),
        "binding_sha256": binding_sha256 or digest(b"binding"),
        "launch_profile_sha256": launch_profile_sha256 or bundle.profile_sha256,
        "toolchain_sha256": bundle.toolchain_sha256,
    }


def test_bundle_is_materialized_without_checkout_import_dependency(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    assert bundle.root.joinpath("broker/worker.py").read_bytes() == b"def serve(): return True\n"
    assert bundle.root.joinpath("broker/worker.py").stat().st_mode & 0o777 == 0o400
    bundle.verify()


def test_closure_rejects_dynamic_transitive_imports(tmp_path: Path) -> None:
    source = tmp_path / "checkout"
    (source / "pkg").mkdir(parents=True)
    (source / "pkg/__init__.py").write_text("from .worker import run\n")
    (source / "pkg/worker.py").write_text(
        "import importlib\nimportlib.import_module('pkg.hidden')\n"
    )
    (source / "pkg/hidden.py").write_text("pass\n")
    with pytest.raises(bundle_v1.BundleError, match="dynamic import"):
        bundle_v1.derive_source_closure(source, "pkg/__init__.py")


def test_only_literal_process_libc_loader_is_trusted(tmp_path: Path) -> None:
    source = tmp_path / "checkout"
    source.mkdir()
    entry = source / "entry.py"
    entry.write_text("import ctypes\nctypes.CDLL(None, use_errno=True)\n")
    assert bundle_v1.derive_source_closure(source, "entry.py") == ("entry.py",)
    entry.write_text("import ctypes\nctypes.CDLL('libother.so', use_errno=True)\n")
    with pytest.raises(bundle_v1.BundleError, match="toolchain allowlist"):
        bundle_v1.derive_source_closure(source, "entry.py")


def test_sealed_zip_launcher_executes_only_descriptor_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "checkout"
    source.mkdir()
    entry = source / "entry.py"
    entry.write_text("print('sealed-entrypoint')\n")
    profile_sha = digest(b"profile")
    toolchain_sha = bundle_v1.compute_toolchain_sha256(())
    bundle = bundle_v1.materialize_bundle(
        source, tmp_path / "sealed", ("entry.py",),
        profile_sha256=profile_sha, toolchain_sha256=toolchain_sha,
        entrypoint="entry.py",
    )
    binding_sha = digest(b"binding")
    runtime_sha = digest(b"runtime")
    receipt_value = bundle_v1.FreezeReceipt(
        runtime_attestation_sha256=runtime_sha,
        bundle_sha256=bundle.digest,
        binding_sha256=binding_sha,
        launch_profile_sha256=profile_sha,
        toolchain_sha256=toolchain_sha,
    )
    lease = bundle_v1.FreezeLease(tmp_path / "lease.lock", bundle, receipt_value).acquire(
        runtime_attestation_sha256=runtime_sha,
        binding_sha256=binding_sha,
        launch_profile_sha256=profile_sha,
        toolchain_sha256=toolchain_sha,
    )
    handle = bundle_v1.LaunchLeaseHandle(lease)
    child = bundle_v1.launch_with_escrow_lease(lease=handle, bundle=bundle)
    stdout, _ = child.communicate(timeout=5)
    assert child.returncode == 0
    assert stdout == b"sealed-entrypoint\n"
    assert handle.phase == "prepared"
    handle.mark_ready(**identities(bundle, runtime_sha256=runtime_sha, binding_sha256=binding_sha,
                                   launch_profile_sha256=profile_sha))
    handle.mark_claimed(**identities(bundle, runtime_sha256=runtime_sha, binding_sha256=binding_sha,
                                     launch_profile_sha256=profile_sha))
    handle.mark_escrow_finalized(**identities(bundle, runtime_sha256=runtime_sha,
                                              binding_sha256=binding_sha,
                                              launch_profile_sha256=profile_sha))


@pytest.mark.parametrize("target", ["source", "sealed", "manifest"])
def test_freeze_checks_detect_source_bundle_and_manifest_mutation(
    tmp_path: Path, target: str
) -> None:
    bundle = make_bundle(tmp_path)
    lease = bundle_v1.FreezeLease(tmp_path / "lease.lock", bundle, receipt(bundle)).acquire(
        **identities(bundle)
    )
    if target == "source":
        bundle.sources["broker/worker.py"].write_bytes(b"def serve(): return False\n")
    elif target == "sealed":
        path = bundle.root / "broker/worker.py"
        path.chmod(0o600)
        path.write_bytes(b"def serve(): return False\n")
    else:
        path = bundle.root / "bundle-manifest-v1.json"
        path.chmod(0o600)
        path.write_bytes(b"{}")
    with pytest.raises(bundle_v1.BundleError, match=r"changed|mode is invalid"):
        lease.check(**identities(bundle))
    lease.close()


def test_symlinked_source_and_destination_replacement_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "checkout"
    source.mkdir()
    external = tmp_path / "external.py"
    external.write_text("pass\n")
    (source / "module.py").symlink_to(external)
    with pytest.raises(bundle_v1.BundleError, match="symlink"):
        bundle_v1.materialize_bundle(
            source, tmp_path / "sealed", ("module.py",),
            profile_sha256=digest(b"p"), toolchain_sha256=digest(b"t")
        )

    bundle = make_bundle(tmp_path / "other")
    lease_path = tmp_path / "other/lease.lock"
    lease = bundle_v1.FreezeLease(lease_path, bundle, receipt(bundle)).acquire(
        **identities(bundle)
    )
    lease_path.unlink()
    lease_path.write_bytes(b"replacement")
    with pytest.raises(bundle_v1.BundleError, match="identity changed"):
        lease.check(**identities(bundle))
    lease.close()


def test_receipt_is_strict_and_all_identity_dimensions_must_match(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    value = {
        "schema_version": 1,
        "protocol": bundle_v1.RECEIPT_PROTOCOL,
        "runtime_attestation_path": "/tmp/runtime-attestation.json",
        "runtime_attestation_sha256": digest(b"runtime"),
        "bundle_manifest_path": str(bundle.root / "bundle-manifest-v1.json"),
        "bundle_sha256": bundle.digest,
        "binding_path": "/tmp/binding.json",
        "binding_sha256": digest(b"binding"),
        "launch_profile_path": "/tmp/launch-profile.json",
        "launch_profile_protocol": bundle_v1.LAUNCH_PROFILE_PROTOCOL,
        "launch_profile_sha256": bundle.profile_sha256,
        "toolchain_sha256": bundle.toolchain_sha256,
        "lease_path": "/tmp/lease.lock",
        "hold_until": "escrow_finalized",
    }
    with pytest.raises(bundle_v1.BundleError, match="keys"):
        bundle_v1.FreezeReceipt.parse({**value, "generation": 5})
    with pytest.raises(bundle_v1.BundleError, match="audit-only"):
        bundle_v1.FreezeReceipt.parse({**value, "launch_profile_protocol": "legacy-v7"})
    lease = bundle_v1.FreezeLease(tmp_path / "lease.lock", bundle, receipt(bundle))
    wrong = identities(bundle) | {"binding_sha256": digest(b"other")}
    with pytest.raises(bundle_v1.BundleError, match="mismatch"):
        lease.acquire(**wrong)
    assert not lease.path.exists()


def test_lease_excludes_competitor_until_explicit_release(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    path = tmp_path / "lease.lock"
    first = bundle_v1.FreezeLease(path, bundle, receipt(bundle)).acquire(**identities(bundle))
    second = bundle_v1.FreezeLease(path, bundle, receipt(bundle))
    with pytest.raises(bundle_v1.BundleError, match="already held"):
        second.acquire(**identities(bundle))
    first.close()
    second.acquire(**identities(bundle))
    second.close()


def test_inherited_descriptor_keeps_freeze_after_prepare_process_closes(
    tmp_path: Path,
) -> None:
    bundle = make_bundle(tmp_path)
    path = tmp_path / "lease.lock"
    prepared = bundle_v1.FreezeLease(path, bundle, receipt(bundle)).acquire(
        **identities(bundle)
    )
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(0.4)"],
        pass_fds=prepared.pass_fds,
    )
    prepared.close()  # Simulates prepare CLI exit after successful broker startup.
    competitor = bundle_v1.FreezeLease(path, bundle, receipt(bundle))
    with pytest.raises(bundle_v1.BundleError, match="already held"):
        competitor.acquire(**identities(bundle))
    assert child.wait(timeout=2) == 0
    competitor.acquire(**identities(bundle))
    competitor.close()


def test_acquire_launch_lease_reads_receipt_and_retains_lock_through_finalize(
    tmp_path: Path,
) -> None:
    bundle = make_bundle(tmp_path)
    runtime = tmp_path / "runtime.json"
    binding = tmp_path / "binding.json"
    profile = tmp_path / "launch-profile.json"
    runtime.write_bytes(b'{"attested":true}')
    binding.write_bytes(b'{"binding":"exact"}')
    profile_value = {
        "schema_version": 2,
        "protocol": bundle_v1.LAUNCH_PROFILE_PROTOCOL,
        "production_profile_sha256": digest(b"production-v1-root"),
        "toolchain_sha256": bundle_v1.compute_toolchain_sha256(()),
        "entrypoint": "broker/__init__.py",
        "external_imports": [],
    }
    profile.write_bytes(bundle_v1._canonical(profile_value))
    receipt_value = {
        "schema_version": 1,
        "protocol": bundle_v1.RECEIPT_PROTOCOL,
        "runtime_attestation_path": str(runtime),
        "runtime_attestation_sha256": digest(runtime.read_bytes()),
        "bundle_manifest_path": str(bundle.root / "bundle-manifest-v1.json"),
        "bundle_sha256": bundle.digest,
        "binding_path": str(binding),
        "binding_sha256": digest(binding.read_bytes()),
        "launch_profile_path": str(profile),
        "launch_profile_protocol": bundle_v1.LAUNCH_PROFILE_PROTOCOL,
        "launch_profile_sha256": digest(profile.read_bytes()),
        "toolchain_sha256": bundle.toolchain_sha256,
        "lease_path": str(tmp_path / "bundle-freeze.lock"),
        "hold_until": "escrow_finalized",
    }
    # The test bundle profile identity is the launch-profile byte identity.
    bundle = bundle_v1.materialize_bundle(
        tmp_path / "checkout", tmp_path / "sealed-v2",
        ("broker/__init__.py", "broker/worker.py"),
        profile_sha256=profile_value["production_profile_sha256"],
        toolchain_sha256=bundle.toolchain_sha256,
        entrypoint="broker/__init__.py",
    )
    receipt_value["bundle_manifest_path"] = str(bundle.root / "bundle-manifest-v1.json")
    receipt_value["bundle_sha256"] = bundle.digest
    receipt_path = tmp_path / "freeze-receipt.json"
    receipt_raw = bundle_v1._canonical(receipt_value)
    receipt_path.write_bytes(receipt_raw)
    receipt_path.chmod(0o400)
    handle = bundle_v1.acquire_launch_lease(
        receipt_path=receipt_path,
        receipt_sha256=digest(receipt_raw),
        bundle_root=bundle.root,
        source_root=tmp_path / "checkout",
        expected_bundle_sha256=bundle.digest,
        runtime_attestation_path=runtime,
        runtime_attestation_sha256=digest(runtime.read_bytes()),
        binding_path=binding,
        binding_sha256=digest(binding.read_bytes()),
        launch_profile_path=profile,
        launch_profile_sha256=digest(profile.read_bytes()),
        toolchain_sha256=bundle.toolchain_sha256,
        require_exclusive_freeze=True,
        hold_until="escrow_finalized",
    )
    assert handle.phase == "prepared"
    inherited = handle.pass_fds()
    assert inherited == (handle.lease.fd,)
    with pytest.raises(bundle_v1.BundleError, match="remain held"):
        handle.close()
    actual = identities(
        bundle,
        runtime_sha256=digest(runtime.read_bytes()),
        binding_sha256=digest(binding.read_bytes()),
        launch_profile_sha256=digest(profile.read_bytes()),
    )
    handle.mark_ready(**actual)
    runtime_raw = runtime.read_bytes()
    runtime.write_bytes(b'{"attested":false}')
    with pytest.raises(bundle_v1.BundleError, match="changed"):
        handle.mark_claimed(**actual)
    runtime.write_bytes(runtime_raw)
    handle.mark_claimed(**actual)
    assert handle.lease.fd >= 0
    binding_raw = binding.read_bytes()
    binding.write_bytes(b'{"binding":"replaced"}')
    with pytest.raises(bundle_v1.BundleError, match="changed"):
        handle.mark_escrow_finalized(**actual)
    binding.write_bytes(binding_raw)
    handle.mark_escrow_finalized(**actual)
    assert handle.phase == "escrow_finalized"
    assert handle.lease.fd == -1
