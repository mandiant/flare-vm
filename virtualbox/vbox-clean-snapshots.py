#!/usr/bin/python3
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


import argparse
import re
import sys
import textwrap

from vboxcommon import get_vm_state, run_vboxmanage

DESCRIPTION = "Clean a VirtualBox VM up by deleting a snapshot and its children recursively skipping snapshots with a substring in the name."

EPILOG = textwrap.dedent(
    """
    Example usage:
      # Delete all snapshots excluding the default protected ones (with 'clean' or 'done' in the name, case insensitive) in the 'FLARE-VM.20240604' VM
      vbox-clean-snapshots.py FLARE-VM.20240604

      # Delete all snapshots that do not include 'clean', 'done', or 'important' (case insensitive) in the name in the 'FLARE-VM.20240604' VM
      vbox-clean-snapshots.py FLARE-VM.20240604 --protected_snapshots "clean,done,important"

      # Delete the 'Snapshot 3' snapshot and its children recursively skipping the default protected ones in the 'FLARE-VM.20240604' VM
      vbox-clean-snapshots.py FLARE-VM.20240604 --root_snapshot "Snapshot 3"

      # Delete the 'CLEAN with IDA 8.4"' children snapshots recursively skipping the default protected ones in the 'FLARE-VM.20240604' VM
      # NOTE: the 'CLEAN with IDA 8.4' root snapshot is skipped in this case
      vbox-clean-snapshots.py FLARE-VM.20240604 --root_snapshot "CLEAN with IDA 8.4"

      # Delete all snapshots in the 'FLARE-VM.20240604' VM
      vbox-clean-snapshots.py FLARE-VM.20240604 --protected_snapshots ""
    """
)


def is_protected(protected_snapshots, snapshot_name):
    """Check if snapshot_name contains any of the strings in the protected_snapshots list (case insensitive)"""
    return any(p.lower() in snapshot_name.lower() for p in protected_snapshots)


def get_snapshot_children(vm_name, root_snapshot_name, protected_snapshots):
    """Get the children of a snapshot (including the snapshot) using 'VBoxManage snapshot' with the 'list' option.

    Args:
      vm_name: The name of the VM.
      root_snapshot_name: The name of the root snapshot we want the children of. If no provided or not found, return all snapshots.
      protected_snapshots: Snapshots we ignore and do not include in the returned list.

    Returns:
      A list of snapshot names that are children of the given snapshot. The list is ordered by dependent relationships.
    """
    # Example of `VBoxManage snapshot VM_NAME list --machinereadable` output:
    # SnapshotName="ROOT"
    # SnapshotUUID="86b38fc9-9d68-4e4b-a033-4075002ab570"
    # SnapshotName-1="Snapshot 1"
    # SnapshotUUID-1="e383e702-fee3-4e0b-b1e0-f3b869dbcaea"
    # CurrentSnapshotName="Snapshot 1"
    # CurrentSnapshotUUID="e383e702-fee3-4e0b-b1e0-f3b869dbcaea"
    # CurrentSnapshotNode="SnapshotName-1"
    # SnapshotName-1-1="Snapshot 2"
    # SnapshotUUID-1-1="8cc12787-99df-466e-8a51-80e373d3447a"
    # SnapshotName-2="Snapshot 3"
    # SnapshotUUID-2="f42533a8-7c14-4855-aa66-7169fe8187fe"
    #
    # ROOT
    #   ├─ Snapshot 1
    #   │   └─ Snapshot 2
    #   └─ Snapshot 3
    snapshots_info = run_vboxmanage(["snapshot", vm_name, "list", "--machinereadable"])

    root_snapshot_index = ""
    if root_snapshot_name:
        # Find root snapshot: first snapshot with name root_snapshot_name (case sensitive)
        root_snapshot_regex = rf'^SnapshotName(?P<index>(?:-\d+)*)="{root_snapshot_name}"\n'
        root_snapshot = re.search(root_snapshot_regex, snapshots_info, flags=re.M)
        if root_snapshot:
            root_snapshot_index = root_snapshot["index"]
        else:
            print(f"\n⚠️  Root snapshot not found: {root_snapshot_name} 🫧 Cleaning all snapshots in the VM")

    # Find all root and child snapshots as (snapshot_name, snapshot_id)
    # Children of a snapshot share the same prefix index
    index_regex = rf"{root_snapshot_index}(?:-\d+)*"
    snapshot_regex = f'^SnapshotName{index_regex}="(.*?)"\nSnapshotUUID{index_regex}="(.*?)"'
    snapshots = re.findall(snapshot_regex, snapshots_info, flags=re.M)

    # Return non protected snapshots as list of (snapshot_name, snapshot_id)
    return [snapshot for snapshot in snapshots if not is_protected(protected_snapshots, snapshot[0])]


def delete_snapshot_and_children(vm_name, snapshot_name, protected_snapshots):
    snaps_to_delete = get_snapshot_children(vm_name, snapshot_name, protected_snapshots)

    if protected_snapshots:
        print("\nSnapshots with the following strings in the name (case insensitive) won't be deleted:")
        for protected_snapshot in protected_snapshots:
            print(f"  {protected_snapshot}")

    if snaps_to_delete:
        print(f"\nCleaning {vm_name} 🫧 Snapshots to delete:")
        for snapshot_name, _ in snaps_to_delete:
            print(f"  {snapshot_name}")

        vm_state = get_vm_state(vm_name)
        if vm_state not in ("poweroff", "saved"):
            print(
                f"\nVM state: {vm_state}\n⚠️  Snapshot deleting is slower in a running VM and may fail in a changing state"
            )

        answer = input("\nConfirm deletion (press 'y'): ")
        if answer.lower() == "y":
            print("\nDELETING SNAPSHOTS... (this may take some time, go for an 🍦!)")
            # Delete snapshots in reverse order to avoid issues with child snapshots,
            # as a snapshot with more than 1 child can not be deleted
            for snapshot_name, snapshot_id in reversed(snaps_to_delete):
                try:
                    run_vboxmanage(["snapshot", vm_name, "delete", snapshot_id])
                    print(f"🫧 DELETED '{snapshot_name}'")
                except Exception as e:
                    print(f"❌ ERROR '{snapshot_name}'\n{e}")
    else:
        print(f"\n{vm_name} is clean 🫧")

    print("\nSee you next time you need to clean up your VMs! ✨\n")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    epilog = EPILOG
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vm_name", help="Name of the VM to clean up")
    parser.add_argument(
        "--root_snapshot",
        help="""Snapshot name (case sensitive) to delete (and its children recursively).
                Leave empty to clean all snapshots in the VM.""",
    )
    parser.add_argument(
        "--protected_snapshots",
        default="clean,done",
        type=lambda s: s.split(",") if s else [],
        help='''Comma-separated list of strings.
                Snapshots with any of the strings included in the name (case insensitive) are not deleted.
                Default: "clean,done"''',
    )
    args = parser.parse_args(args=argv)

    delete_snapshot_and_children(args.vm_name, args.root_snapshot, args.protected_snapshots)


if __name__ == "__main__":
    main()
