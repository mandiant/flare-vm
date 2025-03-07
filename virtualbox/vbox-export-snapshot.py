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
import sys

from vboxcommon import LONG_WAIT, ensure_vm_running, export_vm, get_vm_uuid, restore_snapshot, set_network_to_hostonly

DESCRIPTION = """Export a snapshot to OVA (named after the snapshot) with a single Host-Only network interface.
Generate a file containing the SHA256 hash of the OVA that can be used for verification."""

EPILOG = """
Example usage:
  # Export snapshot "FLARE-VM" from the "FLARE-VM.testing" VM with a description
  ./vbox-export-snapshot.py "FLARE-VM.testing" "FLARE-VM" --description "Windows 10 VM with FLARE-VM default configuration"
"""


def export_snapshot(vm_name, snapshot, description, export_dir_name):
    """Restore a snapshot, set the network to hostonly and then export it with the snapshot as name."""
    vm_uuid = get_vm_uuid(vm_name)
    if not vm_uuid:
        print(f'❌ ERROR: "{vm_name}" not found')
        exit()

    print(f'\nExporting snapshot "{snapshot}" from "{vm_name}" {vm_uuid}...')
    try:
        restore_snapshot(vm_uuid, snapshot)

        set_network_to_hostonly(vm_uuid)

        # Start the VM to ensure everything is good
        print(f"VM {vm_uuid} 🔄 power cycling before export{LONG_WAIT}")
        ensure_vm_running(vm_uuid)
        export_vm(vm_uuid, snapshot, description, export_dir_name)
    except Exception as e:
        print(f'VM {vm_uuid} ❌ ERROR exporting "{snapshot}":{e}\n')


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vm_name", help="name of the VM to export a snapshot from.")
    parser.add_argument("snapshot", help="name of the snapshot to export.")
    parser.add_argument("--description", help="description of the exported OVA. Empty by default.")
    parser.add_argument(
        "--export_dir_name",
        help="name of the directory in HOME to export the VMs The directory is created if it does not exist. Default: {EXPORTED_DIR_NAME}",
    )
    args = parser.parse_args(args=argv)

    export_snapshot(args.vm_name, args.snapshot, args.description, args.export_dir_name)


if __name__ == "__main__":
    main()
