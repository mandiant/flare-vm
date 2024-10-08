#!/usr/bin/python3
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
    """Gets the machine UUID for a given VM name using 'VBoxManage list vms'."""
    try:
        # regex VM name and extract the GUID
        # "FLARE-VM.testing" {b76d628b-737f-40a3-9a16-c5f66ad2cfcc}
        vms_output = run_vboxmanage(["list", "vms"])
        match = re.search(rf'"{vm_name}" \{{(.*?)\}}', vms_output)
        if match:
            uuid = "{" + match.group(1) + "}"
            return uuid
        else:
            raise Exception(f"Could not find VM '{vm_name}'")
    except Exception as e:
        raise Exception(f"Could not find VM '{vm_name}'") from e


def change_network_adapters_to_hostonly(machine_guid):
    """Changes all active network adapters to Host-Only. Must be poweredoff"""
    ensure_hostonlyif_exists()
    try:
        # disable all the nics to get to a clean state
        vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
        for nic_number, nic_value in re.findall(
            '^nic(\d+)="(\S+)"', vminfo, flags=re.M
        ):
            if nic_value != "none":  # Ignore NICs with value "none"
                run_vboxmanage(["modifyvm", machine_guid, f"--nic{nic_number}", "none"])
                print(f"Changed nic{nic_number}")

        # set first nic to hostonly
        run_vboxmanage(["modifyvm", machine_guid, f"--nic1", "hostonly"])

        # ensure changes applied
        vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
        for nic_number, nic_value in re.findall(
            '^nic(\d+)="(\S+)"', vminfo, flags=re.M
        ):
            if nic_number == "1" and nic_value != "hostonly":
                print("Invalid nic configuration detected, nic1 not hostonly")
                raise Exception(
                    "Invalid nic configuration detected, first nic not hostonly"
                )
            elif nic_number != "1" and nic_value != "none":
                print(
                    f"Invalid nic configuration detected, nic{nic_number} not disabled"
                )
                raise Exception(
                    f"Invalid nic configuration detected, nic{nic_number} not disabled"
                )
        print("Nic configuration verified correct")
        return
    except Exception as e:
        raise Exception("Failed to change VM network adapters to hostonly") from e


def restore_snapshot(machine_guid, snapshot_name):
    status = run_vboxmanage(["snapshot", machine_guid, "restore", snapshot_name])
    print(f"Restored '{snapshot_name}'")
    return status


if __name__ == "__main__":
    date = datetime.today().strftime("%Y%m%d")

    for snapshot_name, extension, description in SNAPSHOTS:
        print(f"Starting operations on {snapshot_name}")
        try:
            vm_uuid = get_vm_uuid(VM_NAME)
            # Shutdown machine
            ensure_vm_shutdown(vm_uuid)

            # Restore snapshot (must be shutdown)
            restore_snapshot(vm_uuid, snapshot_name)

            # Shutdown machine (incase the snapshot was taken while running)
            ensure_vm_shutdown(vm_uuid)

            # change all adapters to hostonly (must be shutdown)
            change_network_adapters_to_hostonly(vm_uuid)

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
