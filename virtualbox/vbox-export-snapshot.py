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
import hashlib
import os
import re
import sys

from vboxcommon import (
    ensure_hostonlyif_exists,
    ensure_vm_running,
    ensure_vm_shutdown,
    get_vm_uuid,
    restore_snapshot,
    run_vboxmanage,
)

DESCRIPTION = """Export a snapshot to OVA (named after the snapshot) with a single Host-Only network interface.
Generate a file containing the SHA256 hash of the OVA that can be used for verification."""

EPILOG = """
Example usage:
  # Export snapshot "FLARE-VM" from the "FLARE-VM.testing" VM with a description
  ./vbox-export-snapshot.py "FLARE-VM.testing" "FLARE-VM" --description "Windows 10 VM with FLARE-VM default configuration"
"""

# Message to add to the output when waiting for a long operation to complete.
LONG_WAIT = "... (it will take some time, go for an 🍦!)"

# Default name of the directory in HOME to export VMs to
EXPORT_DIR_NAME = "EXPORTED VMS"


def sha256_file(filename):
    with open(filename, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def set_network_to_hostonly(vm_uuid):
    """Set the NIC 1 to hostonly and disable the rest."""
    # VM must be shutdown before changing the adapters
    ensure_vm_shutdown(vm_uuid)

    # Ensure a hostonly interface exists to prevent issues starting the VM
    ensure_hostonlyif_exists()

    # Example of `VBoxManage showvminfo <VM_UUID> --machinereadable` relevant output:
    # nic1="none"
    # bridgeadapter2="wlp9s0"
    # macaddress2="0800271DDA9D"
    # cableconnected2="on"
    # nic2="bridged"
    # nictype2="82540EM"
    # nicspeed2="0"
    # nic3="none"
    # nic4="none"
    # nic5="none"
    # nic6="none"
    # nic7="none"
    # nic8="none"
    vm_info = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])

    # Set all NICs to none to avoid running into strange situations
    for nic_number, nic_value in re.findall(r'^nic(\d+)="(\S+)"', vm_info, flags=re.M):
        if nic_value != "none":  # Ignore NICs that are already none
            run_vboxmanage(["modifyvm", vm_uuid, f"--nic{nic_number}", "none"])

    # Set NIC 1 to hostonly
    run_vboxmanage(["modifyvm", vm_uuid, "--nic1", "hostonly"])

    # Ensure changes applied
    vm_info = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])
    nic_values = re.findall(r'^nic\d+="(\S+)"', vm_info, flags=re.M)
    if nic_values[0] != "hostonly" or any(nic_value != "none" for nic_value in nic_values[1:]):
        raise RuntimeError(f"Unable to change NICs to a single hostonly in VM {vm_uuid}")

    print(f"VM {vm_uuid} ⚙️  network set to single hostonly adapter")


def export_vm(vm_uuid, exported_vm_name, description="", export_dir_name=EXPORT_DIR_NAME):
    """Export VM as OVA and generate a file with the SHA256 of the exported OVA."""
    export_directory = os.path.expanduser(f"~/{export_dir_name}")
    # Ensure export directory exists
    os.makedirs(export_directory, exist_ok=True)

    exported_ova_filepath = os.path.join(export_directory, f"{exported_vm_name}.ova")

    # Provide better error if OVA already exists (for example if the script is called twice)
    if os.path.exists(exported_ova_filepath):
        raise FileExistsError(f'"{exported_ova_filepath}" already exists')

    # Turn off VM and export it to .ova
    ensure_vm_shutdown(vm_uuid)
    print(f"VM {vm_uuid} 🚧 exporting {LONG_WAIT}")
    run_vboxmanage(
        [
            "export",
            vm_uuid,
            f"--output={exported_ova_filepath}",
            "--vsys=0",  # We need to specify the index of the VM, 0 as we only export 1 VM
            f"--vmname={exported_vm_name}",
            f"--description={description}",
        ]
    )
    print(f'VM {vm_uuid} ✅ EXPORTED "{exported_ova_filepath}"')

    # Generate file with SHA256
    sha256 = sha256_file(exported_ova_filepath)
    sha256_filepath = f"{exported_ova_filepath}.sha256"
    with open(sha256_filepath, "w") as f:
        f.write(sha256)

    print(f'VM {vm_uuid} ✅ GENERATED "{sha256_filepath}": {sha256}\n')


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
