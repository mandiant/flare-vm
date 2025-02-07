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

import re
import subprocess
import time


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


def run_vboxmanage(cmd):
    """Run a VBoxManage command and return the output.

    Args:
      cmd: list of string arguments to pass to VBoxManage
    """
    cmd = ["VBoxManage"] + cmd
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode:
        # Use only the first "VBoxManage: error:" line to prevent using the long
        # VBoxManage help message or noisy information like the details and context.
        error = f"Command '{cmd_to_str(cmd)}' failed"
        match = re.search("^VBoxManage: error: (?P<stderr_info>.*)", result.stderr, flags=re.M)
        if match:
            error += f": {match['stderr_info']}"
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
