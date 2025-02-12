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

import hashlib
import os
import re
import subprocess
import sys
import time
from datetime import datetime

# Message to add to the output when waiting for a long operation to complete.
LONG_WAIT = "... (it will take some time, go for an 🍦!)"

# Default name of the directory in HOME to export VMs to
EXPORT_DIR_NAME = "EXPORTED VMS"


def format_arg(arg):
    """Add quotes to the string arg if it contains special characters like spaces."""
    if any(c in arg for c in (" ", "\\", "/")):
        if "'" not in arg:
            return f"'{arg}'"
        if '"' not in arg:
            return f'"{arg}"'
    return arg


def cmd_to_str(cmd):
    """Convert a list of string arguments to a string."""
    return " ".join(format_arg(arg) for arg in cmd)


def __run_vboxmanage(cmd, real_time=False):
    """Run a command using 'subprocess.run' and return the output.

    Args:
        cmd: list with the command and its arguments
        real_time: Boolean that determines if displaying the output in realtime or returning it.
    """
    if real_time:
        return subprocess.run(cmd, stderr=sys.stderr, stdout=sys.stdout)
    else:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def run_vboxmanage(cmd, real_time=False):
    """Run a VBoxManage command and return the output.

    Args:
        cmd: list of string arguments to pass to VBoxManage
        real_time: Boolean that determines if displaying the output in realtime or returning it.
    """
    cmd = ["VBoxManage"] + cmd
    result = __run_vboxmanage(cmd, real_time)

    if result.returncode:
        # Check if we are affect by the following VERR_NO_LOW_MEMORY bug: https://www.virtualbox.org/ticket/22185
        # and re-run the command every minute until the VERR_NO_LOW_MEMORY error is resolved
        while result.stdout and "VERR_NO_LOW_MEMORY" in result.stdout:
            print("❌ VirtualBox VERR_NO_LOW_MEMORY error (likely https://www.virtualbox.org/ticket/22185)")
            print("🩹 Fit it running 'echo 3 | sudo tee /proc/sys/vm/drop_caches'")
            print("⏳ I'll re-try the command in ~ 1 minute\n")
            time.sleep(60)  # wait 1 minutes

            # Re-try command
            result = __run_vboxmanage(cmd, real_time)

    if result.returncode:
        error = f"Command '{cmd_to_str(cmd)}' failed"
        # Use only the first "VBoxManage: error:" line to prevent using the long
        # VBoxManage help message or noisy information like the details and context.
        if result.stdout:
            match = re.search("^VBoxManage: error: (?P<err_info>.*)", result.stdout, flags=re.M)
            if match:
                error += f": {match['err_info']}"
        raise RuntimeError(error)

    return result.stdout


def get_hostonlyif_name():
    """Get the name of the host-only interface. Return None if there is no host-only interface"""
    # Example of `VBoxManage list hostonlyifs` relevant output:
    # Name:            vboxnet0
    hostonlyifs_info = run_vboxmanage(["list", "hostonlyifs"])

    match = re.search(r"^Name: *(?P<hostonlyif_name>\S+)", hostonlyifs_info, flags=re.M)
    if match:
        return match["hostonlyif_name"]


def ensure_hostonlyif_exists():
    """Get the name of the host-only interface. Create the interface if it doesn't exist."""
    hostonlyif_name = get_hostonlyif_name()

    if not hostonlyif_name:
        # No host-only interface found, create one
        run_vboxmanage(["hostonlyif", "create"])

        hostonlyif_name = get_hostonlyif_name()
        if not hostonlyif_name:
            raise RuntimeError("Failed to create new hostonly interface.")

        print(f"Hostonly interface created: {hostonlyif_name}")

    return hostonlyif_name


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


def sha256_file(filepath):
    """Return the SHA256 of the content of the file provided as argument."""
    with open(filepath, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def export_vm(vm_uuid, exported_vm_name, description="", export_dir_name=EXPORT_DIR_NAME):
    """Export VM as OVA and generate a file with the SHA256 of the exported OVA."""
    # Create export directory
    export_directory = os.path.expanduser(f"~/{export_dir_name}")
    os.makedirs(export_directory, exist_ok=True)

    exported_ova_filepath = os.path.join(export_directory, f"{exported_vm_name}.ova")

    # Rename OVA if it already exists (for example if the script is called twice) or exporting will fail
    if os.path.exists(exported_ova_filepath):
        time_str = datetime.now().strftime("%H_%M")
        old_ova_filepath = os.path.join(export_directory, f"{exported_vm_name}.{time_str}.ova")
        os.rename(exported_ova_filepath, old_ova_filepath)
        print(f"⚠️  Renamed old OVA to export new one: {old_ova_filepath}")

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


def get_vm_state(vm_uuid):
    """Get the VM state using 'VBoxManage showvminfo'."""
    # Example of `VBoxManage showvminfo <VM_UUID> --machinereadable` relevant output:
    # VMState="poweroff"
    vm_info = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])

    match = re.search(r'^VMState="(?P<state>\S+)"', vm_info, flags=re.M)
    if match:
        return match["state"]

    raise Exception(f"Unable to get state of VM {vm_uuid}")


def get_num_logged_in_users(vm_uuid):
    """Return the number of logged in users using 'VBoxManage guestproperty'."""
    # Examples of 'VBoxManage guestproperty get <VM_UUID> "/VirtualBox/GuestInfo/OS/LoggedInUsers"' output:
    # - 'Value: 1'
    # - 'Value: 0'
    # - 'No value set!'
    logged_in_users_info = run_vboxmanage(["guestproperty", "get", vm_uuid, "/VirtualBox/GuestInfo/OS/LoggedInUsers"])

    if logged_in_users_info:
        match = re.search(r"^Value: (?P<logged_in_users>\d+)", logged_in_users_info)
        if match:
            return int(match["logged_in_users"])
    return 0


def wait_until(vm_uuid, condition):
    """Wait for VM to verify a condition

    Return True if the condition is met within one minute.
    Return False otherwise.
    """
    timeout = 60  # seconds
    check_interval = 5  # seconds
    start_time = time.time()
    while time.time() - start_time < timeout:
        if eval(condition):
            time.sleep(5)  # wait a bit to be careful and avoid any weird races
            return True
        time.sleep(check_interval)
    return False


def ensure_vm_running(vm_uuid):
    """Start the VM if its state is not 'running' and ensure the user is logged in."""
    vm_state = get_vm_state(vm_uuid)
    if not vm_state == "running":
        print(f"VM {vm_uuid} state: {vm_state}. Starting VM...")
        run_vboxmanage(["startvm", vm_uuid, "--type", "gui"])

    # Wait until at least 1 user is logged in.
    if not wait_until(vm_uuid, "get_num_logged_in_users(vm_uuid)"):
        raise RuntimeError(f"Unable to start VM {vm_uuid}.")


def ensure_vm_shutdown(vm_uuid):
    """Shut down the VM if its state is not 'poweroff'. If the VM status is 'saved' start it before shutting it down."""
    vm_state = get_vm_state(vm_uuid)
    if vm_state == "poweroff":
        return

    # If the state is aborted-saved, the VM is not running and can't be turned off
    # Log the state and return
    if vm_state == "aborted-saved":
        print(f"VM {vm_uuid} state: {vm_state}")
        return

    if vm_state == "saved":
        ensure_vm_running(vm_uuid)
        vm_state = get_vm_state(vm_uuid)

    print(f"VM {vm_uuid} state: {vm_state}. Shutting down VM...")
    run_vboxmanage(["controlvm", vm_uuid, "poweroff"])

    if not wait_until(vm_uuid, "get_vm_state(vm_uuid) == 'poweroff'"):
        raise RuntimeError(f"Unable to shutdown VM {vm_uuid}.")


def restore_snapshot(vm_uuid, snapshot_name):
    """Restore a given snapshot in the given VM."""
    # VM must be shutdown before restoring snapshot
    ensure_vm_shutdown(vm_uuid)

    run_vboxmanage(["snapshot", vm_uuid, "restore", snapshot_name])
    print(f'VM {vm_uuid} ✨ restored snapshot "{snapshot_name}"')
