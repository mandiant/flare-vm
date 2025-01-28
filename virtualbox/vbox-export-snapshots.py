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

"""
Export one or more snapshots in the same VirtualBox VM as .ova, changing the network adapter to Host-Only.
Generate a file with the SHA256 of the exported .ova.
The exported VM names start with "FLARE-VM.{date}".
"""

import hashlib
import os
import re
from datetime import datetime

from vboxcommon import *

# Base name of the exported VMs
EXPORTED_VM_NAME = "FLARE-VM"

# Name of the VM to export the snapshots from
VM_NAME = f"{EXPORTED_VM_NAME}.testing"

# Name of the directory in HOME to export the VMs
# The directory is created if it does not exist
EXPORT_DIR_NAME = "EXPORTED VMS"

# Array with snapshots to export as .ova where every entry is a tuple with the info:
# - Snapshot name
# - VM name extension (exported VM name: "FLARE-VM.<date>.<extension")
# - Exported VM description
SNAPSHOTS = [
    (
        "FLARE-VM",
        ".dynamic",
        "Windows 10 VM with FLARE-VM default configuration installed",
    ),
    (
        "FLARE-VM.full",
        ".full.dynamic",
        "Windows 10 VM with FLARE-VM default configuration + the packages 'visualstudio.vm' and 'pdbs.pdbresym.vm' installed",
    ),
    (
        "FLARE-VM.EDU",
        ".EDU",
        "Windows 10 VM with FLARE-VM default configuration installed + FLARE-EDU teaching materials",
    ),
]


def sha256_file(filename):
    with open(filename, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def get_vm_uuid(vm_name):
    """Get the machine UUID for a given VM name using 'VBoxManage list vms'. Return None if not found."""
    # regex VM name and extract the GUID
    # Example of `VBoxManage list vms` output:
    # "FLARE-VM.testing" {b76d628b-737f-40a3-9a16-c5f66ad2cfcc}
    # "FLARE-VM" {a23c0c37-2062-4cf0-882b-9e9747dd33b6}
    vms_info = run_vboxmanage(["list", "vms"])

    match = re.search(rf'^"{vm_name}" (?P<uuid>\{{.*?\}})', vms_info, flags=re.M)
    if match:
        return match.group("uuid")


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


def restore_snapshot(vm_uuid, snapshot_name):
    """Restore a given snapshot in the given VM."""
    # VM must be shutdown before restoring snapshot
    ensure_vm_shutdown(vm_uuid)

    run_vboxmanage(["snapshot", vm_uuid, "restore", snapshot_name])
    print(f'VM {vm_uuid} ✨ restored snapshot "{snapshot_name}"')


if __name__ == "__main__":
    date = datetime.today().strftime("%Y%m%d")

    vm_uuid = get_vm_uuid(VM_NAME)
    if not vm_uuid:
        print(f'ERROR: "{VM_NAME}" not found')
        exit()

    print(f'Exporting snapshots from "{VM_NAME}" {vm_uuid}')
    for snapshot_name, extension, description in SNAPSHOTS:
        try:
            restore_snapshot(vm_uuid, snapshot_name)

            set_network_to_hostonly(vm_uuid)

            # do a power cycle to ensure everything is good
            print("Power cycling before export...")

            # TODO: Add a guest notifier (read: run a script in the guest) to say when windows boots, only then shutdown.
            # this works right now but it's a hardcoded sleep which wasts time and isn't guaranteed to not race. Fine for now.
            ensure_vm_running(vm_uuid)
            ensure_vm_shutdown(vm_uuid)
            print("Power cycling done.")

            # Export .ova
            exported_vm_name = f"{EXPORTED_VM_NAME}.{date}{extension}"
            export_directory = os.path.expanduser(f"~/{EXPORT_DIR_NAME}")
            os.makedirs(export_directory, exist_ok=True)
            filename = os.path.join(export_directory, f"{exported_vm_name}.ova")

            print(f"Exporting {filename} (this will take some time, go for an 🍦!)")
            run_vboxmanage(
                [
                    "export",
                    vm_uuid,
                    f"--output={filename}",
                    "--vsys=0",  # We need to specify the index of the VM, 0 as we only export 1 VM
                    f"--vmname={exported_vm_name}",
                    f"--description={description}",
                ]
            )

            # Generate file with SHA256
            with open(f"{filename}.sha256", "w") as f:
                f.write(sha256_file(filename))

            print(f"Exported {filename}! 🎉")
        except Exception as e:
            print(f"Unexpectedly failed doing operations on {VM_NAME}, snapshot ({snapshot_name}).\n{e}")
            break
        print(f"All operations on {VM_NAME}, snapshot ({snapshot_name}), successful ✅")
    print("Done. Exiting...")
