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
    """Add quotes to the string arg if it contains spaces."""
    if " " in arg:
        return f"'{arg}'"
    return arg

def cmd_to_str(cmd):
    """Convert a list of string arguments to a string."""
    return " ".join(format_arg(arg) for arg in cmd)

def run_vboxmanage(cmd):
    """Runs a VBoxManage command and returns the output.

    Args:
      cmd: list of string arguments to pass to VBoxManage
    """
    cmd = ["VBoxManage"] + cmd
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode:
        # Use only the first "VBoxManage: error:" line to prevent using the long
        # VBoxManage help message or noisy information like the details and context.
        error = f"Command '{cmd_to_str(cmd)}' failed"
        stderr_info = re.search("^VBoxManage: error: (.*)", result.stderr, flags=re.M)
        if stderr_info:
            error += f": {stderr_info.group(1)}"
        raise RuntimeError(error)

    return result.stdout


def get_hostonlyif_name():
    """Get the name of the host-only interface. Return None if there is no host-only interface"""
    # Example of `VBoxManage list hostonlyifs` relevant output:
    # Name:            vboxnet0
    hostonlyifs_info = run_vboxmanage(["list", "hostonlyifs"])

    match = re.search(f"^Name: *(?P<hostonlyif_name>\S+)", hostonlyifs_info, flags=re.M)
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

        print(f"VM {vm_uuid} Created hostonly interface: {hostonlyif_name}")

    return hostonlyif_name


def get_vm_state(vm_uuid):
    """Gets the VM state using 'VBoxManage showvminfo'."""
    # VMState="poweroff"
    # VMStateChangeTime="2025-01-02T16:31:51.000000000"

    vminfo = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])
    for line in vminfo.splitlines():
        if line.startswith("VMState"):
            return line.split("=")[1].strip('"')
    raise Exception(f"Could not start VM '{vm_uuid}'")


def wait_until_vm_state(vm_uuid, target_state):
    """Wait for VM state to change.

    Return True if the state changed to the target_stated within one minute.
    Return False otherwise.
    """
    timeout = 60  # seconds
    check_interval = 5  # seconds
    start_time = time.time()
    while time.time() - start_time < timeout:
        vm_state = get_vm_state(vm_uuid)
        if vm_state == target_state:
            time.sleep(5)  # wait a bit to be careful and avoid any weird races
            return True
        time.sleep(check_interval)
    return False


def ensure_vm_running(vm_uuid):
    """Start the VM if its state is not 'running'."""
    vm_state = get_vm_state(vm_uuid)
    if vm_state == "running":
        return

    print(f"VM {vm_uuid} state: {vm_state}. Starting VM...")
    run_vboxmanage(["startvm", vm_uuid, "--type", "gui"])

    if not wait_until_vm_state(vm_uuid, "running"):
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

    if not wait_until_vm_state(vm_uuid, "poweroff"):
        raise RuntimeError(f"Unable to shutdown VM {vm_uuid}.")

