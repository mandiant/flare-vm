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


def ensure_hostonlyif_exists():
    """Gets the name of, or creates a new hostonlyif"""
    try:
        # Name:            vboxnet0
        # GUID:            f0000000-dae8-4abf-8000-0a0027000000
        # DHCP:            Disabled
        # IPAddress:       192.168.56.1
        # NetworkMask:     255.255.255.0
        # IPV6Address:     fe80::800:27ff:fe00:0
        # IPV6NetworkMaskPrefixLength: 64
        # HardwareAddress: 0a:00:27:00:00:00
        # MediumType:      Ethernet
        # Wireless:        No
        # Status:          Up
        # VBoxNetworkName: HostInterfaceNetworking-vboxnet0

        # Find existing hostonlyif
        hostonlyifs_output = run_vboxmanage(["list", "hostonlyifs"])
        for line in hostonlyifs_output.splitlines():
            if line.startswith("Name:"):
                hostonlyif_name = line.split(":")[1].strip()
                print(f"Found existing hostonlyif {hostonlyif_name}")
                return hostonlyif_name

        # No host-only interface found, create one
        print("No host-only interface found. Creating one...")
        run_vboxmanage(["hostonlyif", "create"])
        hostonlyifs_output = run_vboxmanage(
            ["list", "hostonlyifs"]
        )  # Get the updated list
        for line in hostonlyifs_output.splitlines():
            if line.startswith("Name:"):
                hostonlyif_name = line.split(":")[1].strip()
                print(f"Created hostonlyif {hostonlyif_name}")
                return hostonlyif_name
        print("Failed to create new hostonlyif. Exiting...")
        raise Exception("Failed to create new hostonlyif.")
    except Exception as e:
        raise Exception("Failed to verify host-only interface exists") from e


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

