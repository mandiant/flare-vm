#!/usr/bin/python3

import sys
import argparse
import textwrap
import virtualbox
from virtualbox.library import MachineState


TO_DELETE = []


def get_snapshots_to_delete(snapshot, protected_snapshots):
    for child in snapshot.children:
        get_snapshots_to_delete(child, protected_snapshots)
    snapshot_name = snapshot.name.lower()
    for protected_str in protected_snapshots:
        if protected_str in snapshot_name:
            return
    TO_DELETE.append((snapshot.name, snapshot.id_p))


def delete_snapshot_and_children(vm_name, snapshot_name, protected_snapshots):
    vbox = virtualbox.VirtualBox()
    vm = vbox.find_machine(vm_name)
    snapshot = vm.find_snapshot(snapshot_name)
    get_snapshots_to_delete(snapshot, protected_snapshots)

    if TO_DELETE:
        print(f"\nCleaning {vm_name} 🫧 Snapshots to delete:")
        for name, _ in TO_DELETE:
            print(f"  {name}")

        if vm.state not in (MachineState.powered_off, MachineState.saved):
            print(f"\nVM state: {vm.state}\n⚠️  Snapshot deleting is slower in a running VM and may fail in a changing state")

        answer = input("\nConfirm deletion ('y'):")
        if answer.lower() == "y":
            print("\nDeleting... (this may take some time, go for an 🍦!)")
            session = vm.create_session()
            for name, uuid in TO_DELETE:
                try:
                    progress = session.machine.delete_snapshot(uuid)
                    progress.wait_for_completion(-1)
                    print(f"  🫧 DELETED '{name}'")
                except Exception as e:
                    print(f"  ❌ ERROR '{name}': {e}")
            session.unlock_machine()
    else:
        print(f"\n{vm_name} is clean 🫧")

    print("\nSee you next time you need to clean up your VMs! ✨\n")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    epilog = textwrap.dedent(
        """
        Example usage:
          # Delete all snapshots that do not include 'clean' or 'done' in the name (case insensitive) in the 'FLARE-VM.20240604' VM
          vbox-clean-snapshots.py FLARE-VM.20240604

          # Delete all snapshots that do not include 'clean', 'done', or 'important in the name in the 'FLARE-VM.20240604' VM
          vbox-clean-snapshots.py FLARE-VM.20240604 --protected_snapshots "clean,done,important"

          # Delete the 'CLEAN with IDA 8.4' children snapshots recursively skipping the ones that include 'clean' or 'done' in the name (case insensitive) in the 'FLARE-VM.20240604' VM
          # NOTE: the 'CLEAN with IDA 8.4' root snapshot is skipped in this case
          vbox-clean-snapshots.py FLARE-VM.20240604 --root_snapshot 'CLEAN with IDA 8.4'

          # Delete the 'Snapshot 3' snapshot and its children recursively skipping the ones that include 'clean' or 'done' in the name (case insensitive) in the 'FLARE-VM.20240604' VM
          vbox-clean-snapshots.py FLARE-VM.20240604 --root_snapshot 'Snapshot 3'

          # Delete all snapshots in the 'FLARE-VM.20240604' VM
          vbox-clean-snapshots.py FLARE-VM.20240604 --protected_snapshots ""
        """
    )
    parser = argparse.ArgumentParser(
        description="Clean a VirtualBox VM up by deleting a snapshot and its children recursively skipping snapshots with a substring in the name.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vm_name", help="Name of the VM to clean up")
    parser.add_argument("--root_snapshot", default="", help="Snapshot to delete (and its children recursively). Leave empty to clean all snapshots in the VM.")
    parser.add_argument(
        "--protected_snapshots",
        default="clean,done",
        type=lambda s: s.split(","),
        help='Comma-separated list of strings. Snapshots with any of the strings included in the name (case insensitive) are not deleted. Default: "clean,done"',
    )
    args = parser.parse_args(args=argv)

    delete_snapshot_and_children(args.vm_name, args.root_snapshot, args.protected_snapshots)


if __name__ == "__main__":
    main()
