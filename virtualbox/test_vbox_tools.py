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

import importlib.util
import os
import sys
import types

import pytest

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
