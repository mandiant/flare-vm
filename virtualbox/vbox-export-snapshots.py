#!/usr/bin/python3
"""
Export one or more snapshots in the same VirtualBox VM as .ova, changing the network adapter to Host-Only.
Generate a file with the SHA256 of the exported .ova.
The exported VM names start with "FLARE-VM.{date}".
"""

import os
import hashlib
import virtualbox
from virtualbox.library import VirtualSystemDescriptionType as DescType
from virtualbox.library import NetworkAttachmentType as NetType
from datetime import datetime

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
    ("FLARE-VM", ".dynamic", "Windows 10 VM with FLARE-VM default configuration installed"),
    ("FLARE-VM.full", ".full.dynamic", "Windows 10 VM with FLARE-VM default configuration + the packages 'visualstudio.vm' and 'pdbs.pdbresym.vm' installed"),
    ("FLARE-VM.EDU", ".EDU", "Windows 10 VM with FLARE-VM default configuration installed + FLARE-EDU teaching materials"),
]


def sha256_file(filename):
    with open(filename, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def change_network_adapters(vm, max_adapters):
    for i in range(max_adapters):
        adapter = vm.get_network_adapter(i)
        adapter.attachment_type = NetType.host_only


if __name__ == "__main__":
    date = datetime.today().strftime("%Y%m%d")

    vbox = virtualbox.VirtualBox()
    vm = vbox.find_machine(VM_NAME)
    session = vm.create_session()
    vm = session.machine

    max_adapters = vbox.system_properties.get_max_network_adapters(vm.chipset_type)

    for snapshot_name, extension, description in SNAPSHOTS:
        try:
            # Restore snapshot
            snapshot = vm.find_snapshot(snapshot_name)
            progress = vm.restore_snapshot(snapshot)
            progress.wait_for_completion(-1)

            change_network_adapters(vm, max_adapters)

            print(f"Restored '{snapshot_name}' and changed its adapter(s) to host-only")

            # Export .ova
            exported_vm_name = f"{EXPORTED_VM_NAME}.{date}{extension}"
            export_directory = os.path.expanduser(f"~/{EXPORT_DIR_NAME}")
            os.makedirs(export_directory, exist_ok=True)
            filename = os.path.join(export_directory, f"{exported_vm_name}.ova")
            appliance = vbox.create_appliance()
            sys_description = vm.export_to(appliance, exported_vm_name)
            sys_description.set_final_value(DescType.description, description)
            progress = appliance.write("ovf-1.0", [], filename)
            print(f"Exporting {filename} (this will take some time, go for an 🍦!)")
            progress.wait_for_completion(-1)

            # Generate file with SHA256
            with open(f"{filename}.sha256", "w") as f:
                f.write(sha256_file(filename))

            print(f"Exported {filename}! 🎉")

        except Exception as e:
            print(f"ERROR exporting {snapshot_name}: {e}")
            next

    session.unlock_machine()
