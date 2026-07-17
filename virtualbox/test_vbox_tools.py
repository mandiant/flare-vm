# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the VirtualBox helper parsers.

These tests exercise the pure string/regex parsing of `VBoxManage` output, which is where
subtle bugs tend to hide. `run_vboxmanage` is monkeypatched so no VirtualBox install is needed.

Run with:  pytest virtualbox/test_vbox_tools.py
"""

import hashlib
import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_module(filename, module_name):
    """Import a module from a file path (needed because some scripts have hyphens in the name)."""
    path = os.path.join(HERE, filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# `vbox-adapter-check` imports PyGObject (`gi`), which is not installed in CI/dev environments.
# Stub the pieces it touches at import time so the module can be imported and its parsers tested.
if "gi" not in sys.modules:
    gi_stub = types.ModuleType("gi")
    gi_stub.require_version = lambda *a, **k: None
    repository = types.ModuleType("gi.repository")
    repository.Notify = types.SimpleNamespace(
        init=lambda *a, **k: None,
        Notification=types.SimpleNamespace(new=lambda *a, **k: None),
    )
    gi_stub.repository = repository
    sys.modules["gi"] = gi_stub
    sys.modules["gi.repository"] = repository

# Make `import vboxcommon` resolve for the sibling modules.
sys.path.insert(0, HERE)

vboxcommon = _load_module("vboxcommon.py", "vboxcommon")
adapter_check = _load_module("vbox-adapter-check.py", "vbox_adapter_check")
clean_snapshots = _load_module("vbox-clean-snapshots.py", "vbox_clean_snapshots")
export_snapshot = _load_module("vbox-export-snapshot.py", "vbox_export_snapshot")
build_flare_vm = _load_module("vbox-build-flare-vm.py", "vbox_build_flare_vm")


SHOWVMINFO_SAMPLE = """\
nic1="hostonly"
nictype1="82540EM"
nicspeed1="0"
nic2="nat"
nic3="none"
nic4="none"
VMState="poweroff"
"""

LIST_VMS_SAMPLE = """\
"FLARE-VM.testing" {b76d628b-737f-40a3-9a16-c5f66ad2cfcc}
"FLARE-VM.dynamic" {a23c0c37-2062-4cf0-882b-9e9747dd33b6}
"REMnux" {c33c0c37-2062-4cf0-882b-9e9747dd3300}
"""

SNAPSHOT_LIST_SAMPLE = """\
SnapshotName="ROOT"
SnapshotUUID="86b38fc9-9d68-4e4b-a033-4075002ab570"
SnapshotName-1="clean state"
SnapshotUUID-1="e383e702-fee3-4e0b-b1e0-f3b869dbcaea"
SnapshotName-1-1="Snapshot 2"
SnapshotUUID-1-1="8cc12787-99df-466e-8a51-80e373d3447a"
SnapshotName-2="Snapshot 3"
SnapshotUUID-2="f42533a8-7c14-4855-aa66-7169fe8187fe"
"""


# --------------------------- vboxcommon: quoting helpers ---------------------------


def test_format_arg_plain():
    assert vboxcommon.format_arg("simple") == "simple"


def test_format_arg_with_space_is_quoted():
    assert vboxcommon.format_arg("with space") == "'with space'"


def test_cmd_to_str_quotes_only_when_needed():
    assert vboxcommon.cmd_to_str(["VBoxManage", "list", "vms"]) == "VBoxManage list vms"
    assert vboxcommon.cmd_to_str(["export", "my vm"]) == "export 'my vm'"


def test_sha256_file_is_streamed_and_portable(tmp_path):
    content = (b"FLARE-VM" * 200_000) + b"end"
    test_file = tmp_path / "content.bin"
    test_file.write_bytes(content)
    assert vboxcommon.sha256_file(test_file) == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("directory", ["../outside", "..", "/tmp/outside"])
def test_export_directory_rejects_paths_outside_home(directory):
    with pytest.raises(ValueError, match="below HOME"):
        vboxcommon.get_export_directory(directory)


def test_export_directory_defaults_below_home(monkeypatch):
    fake_home = os.path.abspath(os.path.join(os.sep, "home", "analyst"))
    monkeypatch.setattr(vboxcommon.os.path, "expanduser", lambda _path: fake_home)
    assert vboxcommon.get_export_directory(None) == os.path.join(fake_home, vboxcommon.EXPORT_DIR_NAME)


# --------------------------- vboxcommon: VBoxManage output parsers ---------------------------


def test_get_vm_uuid_matches_exact_name(monkeypatch):
    monkeypatch.setattr(vboxcommon, "run_vboxmanage", lambda cmd: LIST_VMS_SAMPLE)
    assert vboxcommon.get_vm_uuid("REMnux") == "{c33c0c37-2062-4cf0-882b-9e9747dd3300}"


def test_get_vm_uuid_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr(vboxcommon, "run_vboxmanage", lambda cmd: LIST_VMS_SAMPLE)
    assert vboxcommon.get_vm_uuid("does-not-exist") is None


def test_get_vm_state(monkeypatch):
    monkeypatch.setattr(vboxcommon, "run_vboxmanage", lambda cmd: SHOWVMINFO_SAMPLE)
    assert vboxcommon.get_vm_state("{uuid}") == "poweroff"


def test_control_guest_does_not_retry_permanent_error(monkeypatch):
    monkeypatch.setattr(vboxcommon, "ensure_vm_running", lambda _uuid: None)
    monkeypatch.setattr(
        vboxcommon,
        "run_vboxmanage",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("VERR_AUTHENTICATION_FAILURE")),
    )
    monkeypatch.setattr(vboxcommon.time, "sleep", lambda _seconds: pytest.fail("permanent errors must not sleep"))
    with pytest.raises(RuntimeError, match="VERR_AUTHENTICATION_FAILURE"):
        vboxcommon.control_guest("{uuid}", "user", "bad-password", ["run", "command"])


def test_control_guest_retries_transient_error_once(monkeypatch):
    calls = []
    sleeps = []
    monkeypatch.setattr(vboxcommon, "ensure_vm_running", lambda _uuid: None)

    def run_with_transient_failure(*_args, **_kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("guest additions are starting")
        return "success"

    monkeypatch.setattr(vboxcommon, "run_vboxmanage", run_with_transient_failure)
    monkeypatch.setattr(vboxcommon.time, "sleep", sleeps.append)
    assert vboxcommon.control_guest("{uuid}", "user", "password", ["run", "command"]) == "success"
    assert len(calls) == 2
    assert sleeps == [120]


def test_control_guest_uses_temporary_password_file(monkeypatch):
    observed_commands = []
    monkeypatch.setattr(vboxcommon, "ensure_vm_running", lambda _uuid: None)

    def inspect_command(command, _real_time=False):
        observed_commands.append(command)
        password_argument = next(argument for argument in command if argument.startswith("--passwordfile="))
        password_path = password_argument.split("=", 1)[1]
        with open(password_path, encoding="utf-8") as password_file:
            assert password_file.read() == "secret"
        return "success"

    monkeypatch.setattr(vboxcommon, "run_vboxmanage", inspect_command)
    assert vboxcommon.control_guest("{uuid}", "user", "secret", ["run", "command"]) == "success"
    assert not any(argument.startswith("--password=") for argument in observed_commands[0])
    password_path = next(
        argument.split("=", 1)[1] for argument in observed_commands[0] if argument.startswith("--passwordfile=")
    )
    assert not os.path.exists(password_path)


@pytest.mark.parametrize(
    "output, expected",
    [
        ("Value: 1", 1),
        ("Value: 0", 0),
        ("No value set!", 0),
    ],
)
def test_get_num_logged_in_users(monkeypatch, output, expected):
    monkeypatch.setattr(vboxcommon, "run_vboxmanage", lambda cmd: output)
    assert vboxcommon.get_num_logged_in_users("{uuid}") == expected


# --------------------------- vbox-adapter-check: get_vms / get_nics ---------------------------


def test_get_vms_returns_all_when_not_dynamic_only(monkeypatch):
    monkeypatch.setattr(adapter_check, "run_vboxmanage", lambda cmd: LIST_VMS_SAMPLE)
    names = [name for name, _uuid in adapter_check.get_vms(dynamic_only=False)]
    assert names == ["FLARE-VM.testing", "FLARE-VM.dynamic", "REMnux"]


def test_get_vms_dynamic_only_keeps_only_dynamic(monkeypatch):
    """Regression test: --dynamic_only must return the .dynamic VMs, not exclude them."""
    monkeypatch.setattr(adapter_check, "run_vboxmanage", lambda cmd: LIST_VMS_SAMPLE)
    names = [name for name, _uuid in adapter_check.get_vms(dynamic_only=True)]
    assert names == ["FLARE-VM.dynamic"]


def test_get_nics_all(monkeypatch):
    monkeypatch.setattr(adapter_check, "run_vboxmanage", lambda cmd: SHOWVMINFO_SAMPLE)
    assert adapter_check.get_nics("{uuid}") == [("1", "hostonly"), ("2", "nat"), ("3", "none"), ("4", "none")]


def test_get_nics_single(monkeypatch):
    monkeypatch.setattr(adapter_check, "run_vboxmanage", lambda cmd: SHOWVMINFO_SAMPLE)
    assert adapter_check.get_nics("{uuid}", only_nic="2") == [("2", "nat")]


def test_do_not_modify_does_not_create_hostonly_interface(monkeypatch):
    monkeypatch.setattr(adapter_check, "get_vms", lambda _dynamic_only: [("FLARE-VM.dynamic", "{uuid}")])
    monkeypatch.setattr(adapter_check, "verify_network_adapters", lambda *_args: None)
    monkeypatch.setattr(
        adapter_check,
        "ensure_hostonlyif_exists",
        lambda: pytest.fail("read-only mode must not create a host-only interface"),
    )
    adapter_check.main(["--do_not_modify"])


# --------------------------- vbox-clean-snapshots: protection + children ---------------------------


def test_is_protected_case_insensitive():
    assert clean_snapshots.is_protected(["clean", "done"], "CLEAN with IDA")
    assert not clean_snapshots.is_protected(["clean", "done"], "Snapshot 3")


def test_get_snapshot_children_excludes_protected(monkeypatch):
    monkeypatch.setattr(clean_snapshots, "run_vboxmanage", lambda cmd: SNAPSHOT_LIST_SAMPLE)
    result = clean_snapshots.get_snapshot_children("VM", "", ["clean", "done"])
    names = [name for name, _uuid in result]
    # "clean state" is protected and must be excluded; everything else is returned.
    assert "clean state" not in names
    assert "Snapshot 3" in names
    assert "ROOT" in names


def test_get_snapshot_children_root_subtree(monkeypatch):
    monkeypatch.setattr(clean_snapshots, "run_vboxmanage", lambda cmd: SNAPSHOT_LIST_SAMPLE)
    # Root "clean state" (index -1) subtree includes itself and "Snapshot 2" (index -1-1);
    # with no protection list, both are returned.
    result = clean_snapshots.get_snapshot_children("VM", "clean state", [])
    names = [name for name, _uuid in result]
    assert "clean state" in names
    assert "Snapshot 2" in names
    assert "Snapshot 3" not in names


def test_get_snapshot_children_missing_root_fails_closed(monkeypatch):
    monkeypatch.setattr(clean_snapshots, "run_vboxmanage", lambda cmd: SNAPSHOT_LIST_SAMPLE)
    with pytest.raises(RuntimeError, match="Root snapshot not found"):
        clean_snapshots.get_snapshot_children("VM", "does-not-exist", [])


def test_export_snapshot_missing_vm_is_an_error(monkeypatch):
    monkeypatch.setattr(export_snapshot, "get_vm_uuid", lambda _name: None)
    with pytest.raises(RuntimeError, match="not found"):
        export_snapshot.export_snapshot("missing", "snapshot", "", vboxcommon.EXPORT_DIR_NAME)


def test_flare_install_wait_has_a_timeout(monkeypatch):
    monkeypatch.setattr(build_flare_vm, "GUEST_PASSWORD", "test-password")
    monkeypatch.setattr(build_flare_vm, "control_guest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(build_flare_vm, "run_command", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(build_flare_vm.time, "monotonic", lambda: 0)
    with pytest.raises(TimeoutError, match="did not finish"):
        build_flare_vm.install_flare_vm("{uuid}", "snapshot", False, install_timeout=0)


@pytest.mark.parametrize(
    "config_path",
    list((Path(HERE) / "configs").glob("*.yaml")),
    ids=lambda path: path.name,
)
def test_example_yaml_config_has_required_shape(config_path):
    with config_path.open(encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file)

    assert isinstance(config.get("VM_NAME"), str) and config["VM_NAME"]
    assert isinstance(config.get("EXPORTED_VM_NAME"), str) and config["EXPORTED_VM_NAME"]
    if config_path.name == "remnux.yaml":
        assert isinstance(config.get("SNAPSHOT"), dict)
        assert isinstance(config.get("CMDS"), list)
    else:
        assert isinstance(config.get("SNAPSHOTS"), list) and config["SNAPSHOTS"]


@pytest.mark.parametrize(
    "workflow_path",
    list((Path(HERE).parent / ".github" / "workflows").glob("*.y*ml")),
    ids=lambda path: path.name,
)
def test_github_workflow_yaml_parses(workflow_path):
    with workflow_path.open(encoding="utf-8") as workflow_file:
        workflow = yaml.safe_load(workflow_file)
    assert isinstance(workflow, dict)
    assert "jobs" in workflow
