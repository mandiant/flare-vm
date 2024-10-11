#!/usr/bin/python3
"""
Export one or more snapshots in the same VirtualBox VM as .ova, changing the network adapter to Host-Only.
Generate a file with the SHA256 of the exported .ova.
The exported VM names start with "FLARE-VM.{date}".
"""

import os
import hashlib
import re
import subprocess
from datetime import datetime
import time

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

# cmd is an array of string arguments to pass
def run_vboxmanage(cmd):
    """Runs a VBoxManage command and returns the output."""
    try:
        result = subprocess.run(["VBoxManage"] + cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        # exit code is an error
        print(f"Error running VBoxManage command: {e} ({e.stderr})")
    raise Exception(f"Error running VBoxManage command")

def get_vm_uuid(vm_name):
    """Gets the machine UUID for a given VM name using 'VBoxManage list vms'."""
    try:
        vms_output = run_vboxmanage(["list", "vms"])
        # regex VM name and extract the GUID
        match = re.search(rf'"{vm_name}" \{{(.*?)\}}', vms_output)
        if match:
            uuid = "{" + match.group(1) + "}"
            return uuid
        else:
            raise Exception(f"Could not find VM '{vm_name}'")
    except Exception as e:
        print(f"Error getting machine UUID: {e}")
    raise Exception(f"Could not find VM '{vm_name}'")

def get_vm_state(machine_guid):
    """Gets the VM state using 'VBoxManage showvminfo'."""
    vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
    for line in vminfo.splitlines():
        if line.startswith("VMState"):
            return line.split("=")[1].strip('"')
    raise Exception(f"Could not start VM '{machine_guid}'")

def ensure_vm_running(machine_guid):
    """Checks if the VM is running and starts it if it's not.
    Waits up to 1 minute for the VM to transition to the 'running' state.
    """
    try:
        vm_state = get_vm_state(machine_guid)
        if vm_state != "running":
            print(f"VM {machine_guid} is not running (state: {vm_state}). Starting VM...")
            run_vboxmanage(["startvm", machine_guid, "--type", "gui"])

            # Wait for VM to start (up to 1 minute)
            timeout = 60  # seconds
            check_interval = 5  # seconds
            start_time = time.time()
            while time.time() - start_time < timeout:
                vm_state = get_vm_state(machine_guid)
                if vm_state == "running":
                    print(f"VM {machine_guid} started.")
                    time.sleep(5) # wait a bit to be careful and avoid any weird races
                    return
                print(f"Waiting for VM (state: {vm_state})")
                time.sleep(check_interval)
            print("Timeout waiting for VM to start. Exiting...")
            raise TimeoutError(f"VM did not start within the timeout period {timeout}s.")
        else:
            print("VM is already running.")
            return
    except Exception as e:
        print(f"Error checking VM state: {e}")
    raise Exception(f"Could not ensure '{machine_guid}' running")

def ensure_vm_shutdown(machine_guid):
    """Checks if the VM is running and shuts it down if it is."""
    try:
        vm_state = get_vm_state(machine_guid)
        if vm_state != "poweroff":
            print(f"VM {machine_guid} is not powered off. Shutting down VM...")
            run_vboxmanage(["controlvm", machine_guid, "poweroff"]) 

            # Wait for VM to shut down (up to 1 minute)
            timeout = 60  # seconds
            check_interval = 5  # seconds
            start_time = time.time()
            while time.time() - start_time < timeout:
                vm_state = get_vm_state(machine_guid)
                if vm_state == "poweroff":
                    print(f"VM {machine_guid} is shut down (status: {vm_state}).")
                    time.sleep(5) # wait a bit to be careful and avoid any weird races
                    return
                time.sleep(check_interval)
            print("Timeout waiting for VM to shut down. Exiting...")
            raise TimeoutError("VM did not shut down within the timeout period.")
        else:
            print(f"VM {machine_guid} is already shut down (state: {vm_state}).")
            return
    except Exception as e:
        print(f"Error checking VM state: {e}")
    raise Exception(f"Could not ensure '{machine_guid}' shutdown")

def ensure_hostonlyif_exists():
    """Gets the name of, or creates a new hostonlyif"""
    try:
        # Find existing hostonlyif
        hostonlyifs_output = run_vboxmanage(["list", "hostonlyifs"])
        for line in hostonlyifs_output.splitlines():
            if line.startswith("Name:"):
                hostonlyif_name = line.split(":")[1].strip()
                print(f"Found existing hostonlyif {hostonlyif_name}")
                return
        
        # No host-only interface found, create one
        print("No host-only interface found. Creating one...")
        run_vboxmanage(["hostonlyif", "create"])  # Create a host-only interface
        hostonlyifs_output = run_vboxmanage(["list", "hostonlyifs"])  # Get the updated list
        for line in hostonlyifs_output.splitlines():
            if line.startswith("Name:"):
                hostonlyif_name = line.split(":")[1].strip()
                print(f"Created hostonlyif {hostonlyif_name}")
                return
        print("Failed to create new hostonlyif. Exiting...")
        raise Exception("Failed to create new hostonlyif.")
    except Exception as e:
        print(f"Error getting host-only interface name: {e}")
    raise Exception("Failed to verify host-only interface exists")

def change_network_adapters_to_hostonly(machine_guid):
    """Changes all active network adapters to Host-Only. Must be poweredoff"""
    ensure_hostonlyif_exists()
    try:
        # disable all the nics to get to a clean state
        vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
        for nic_number, nic_value in re.findall("^nic(\d+)=\"(\S+)\"", vminfo, flags=re.M):
            if nic_value != "none":  # Ignore NICs with value "none"
                run_vboxmanage(["modifyvm", machine_guid, f"--nic{nic_number}", "none"])
                print(f"Changed nic{nic_number}")
        
        # set first nic to hostonly
        run_vboxmanage(["modifyvm", machine_guid, f"--nic1", "hostonly"])
        
        # ensure changes applied
        vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
        for nic_number, nic_value in re.findall("^nic(\d+)=\"(\S+)\"", vminfo, flags=re.M):
            if nic_number == "1" and nic_value != "hostonly":
                print("Invalid nic configuration detected, nic1 not hostonly")
                raise Exception("Invalid nic configuration detected, first nic not hostonly")
            elif nic_number != "1" and nic_value != "none":
                print(f"Invalid nic configuration detected, nic{nic_number} not disabled")
                raise Exception(f"Invalid nic configuration detected, nic{nic_number} not disabled")
        print("Nic configuration verified correct")
        return
    except Exception as e:
        print(f"Error changing network adapters: {e}")
    print("Failed to change VM network adapters to hostonly")
    raise Exception("Failed to change VM network adapters to hostonly")

def restore_snapshot(machine_guid, snapshot_name):
    status =  run_vboxmanage(["snapshot", machine_guid, "restore", snapshot_name])
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
                    "--vsys=0", # we have normal vms with only 1 vsys
                    f"--vmname={exported_vm_name}",
                    f"--description={description}",
                ]
            )
    
            # Generate file with SHA256
            with open(f"{filename}.sha256", "w") as f:
                f.write(sha256_file(filename))
    
            print(f"Exported {filename}! 🎉")
        except Exception as e:
            print(f"Unexpectedly failed doing operations on {snapshot_name}. Exiting...")
            break
        print(f"All operations on {snapshot_name} successful ✅")
    print("Done. Exiting...")