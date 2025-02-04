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
import json
import os
import re
import sys
import textwrap
import time
from datetime import datetime

import jsonschema
from vboxcommon import ensure_hostonlyif_exists, ensure_vm_running, ensure_vm_shutdown, run_vboxmanage

DESCRIPTION = """Export one or more snapshots in the same VirtualBox VM as .ova, changing the network to a single Host-Only interface.
Generate a file with the SHA256 of the exported OVA(s)."""

EPILOG = textwrap.dedent(
    """
    Example usage:
      # Export snapshots using the information in the "configs/export_win10_flare-vm.json" config file
      ./vbox-export-snapshots.py configs/export_win10_flare-vm.json
    """
)

# Duration of the power cycle: the seconds we wait between starting the VM and powering it off.
# It should be long enough for the internet_detector to detect the network change.
POWER_CYCLE_TIME = 240  # 4 minutes

# Message to add to the output when waiting for a long operation to complete.
LONG_WAIT = "... (it will take some time, go for an 🍦!)"


# Format of snapshot information in the configuration file whose path is provided as argument
snapshotsSchema = {
    "type": "object",
    "properties": {
        "VM_NAME": {"type": "string"},
        "EXPORTED_VM_NAME": {"type": "string"},
        "SNAPSHOTS": {
            "type": "array",
            "items": {"type": "array", "items": {"type": "string"}, "minItems": 3, "maxItems": 3},
            "minItems": 1,
        },
        "EXPORT_DIR_NAME": {"type": "string"},
    },
    "required": ["VM_NAME", "EXPORTED_VM_NAME", "SNAPSHOTS"],
}


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


def export_snapshots(vm_name, exported_vm_name, snapshots, export_dir_name):
    date = datetime.today().strftime("%Y%m%d")

    vm_uuid = get_vm_uuid(vm_name)
    if not vm_uuid:
        print(f'ERROR: "{vm_name}" not found')
        exit()

    print(f'\nExporting snapshots from "{vm_name}" {vm_uuid}')

    # Create export directory
    export_directory = os.path.expanduser(f"~/{export_dir_name}")
    os.makedirs(export_directory, exist_ok=True)
    print(f'Export directory: "{export_directory}"\n')

    for snapshot_name, extension, description in snapshots:
        try:
            restore_snapshot(vm_uuid, snapshot_name)

            set_network_to_hostonly(vm_uuid)

            # Do a power cycle to ensure everything is good and
            # give the internet detector time to detect the network change
            print(f"VM {vm_uuid} 🔄 power cycling before export{LONG_WAIT}")
            ensure_vm_running(vm_uuid)
            time.sleep(POWER_CYCLE_TIME)
            ensure_vm_shutdown(vm_uuid)

            exported_vm_name = f"{exported_vm_name}.{date}{extension}"
            exported_ova_filepath = os.path.join(export_directory, f"{exported_vm_name}.ova")

            # Provide better error if OVA already exists (for example if the script is called twice)
            if os.path.exists(exported_ova_filepath):
                raise FileExistsError(f'"{exported_ova_filepath}" already exists')

            # Export .ova
            print(f'VM {vm_uuid} 🚧 exporting "{exported_vm_name}"{LONG_WAIT}')
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
        except Exception as e:
            print(f'VM {vm_uuid} ❌ ERROR exporting "{snapshot_name}":{e}\n')

    print("Done! 🙃")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "config_path",
        help=""" path of the JSON configuration file.
             "VM_NAME" is the name of the VM to export snapshots from.
               Example: "FLARE-VM.testing".
             "EXPORTED_VM_NAME" is the name of the exported VMs.
               Example: "FLARE-VM".
             "SNAPSHOTS" is a list of lists with information of the snapshots to export:
               ["SNAPSHOT_NAME", "EXPORTED_VM_EXTENSION", "DESCRIPTION"].
               Example: ["FLARE-VM", ".dynamic", "Windows 10 VM with FLARE-VM default configuration"].
             "EXPORT_DIR_NAME" (optional) is the name of the directory in HOME to export the VMs.
               The directory is created if it does not exist.
               Default: "EXPORTED VMS".
             """,
    )
    args = parser.parse_args(args=argv)

    try:
        with open(args.config_path) as f:
            config = json.load(f)

        jsonschema.validate(instance=config, schema=snapshotsSchema)
    except Exception as e:
        print(f'Invalid "{args.config_path}": {e}')
        exit()

    export_dir_name = config.get("EXPORT_DIR_NAME", "EXPORTED VMS")
    export_snapshots(config["VM_NAME"], config["EXPORTED_VM_NAME"], config["SNAPSHOTS"], export_dir_name)


if __name__ == "__main__":
    main()
