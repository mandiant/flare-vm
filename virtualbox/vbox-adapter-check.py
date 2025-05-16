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
import re
import sys
import textwrap

import gi
from vboxcommon import ensure_hostonlyif_exists, get_vm_state, run_vboxmanage

gi.require_version("Notify", "0.7")
from gi.repository import Notify  # noqa: E402

DYNAMIC_VM_NAME = ".dynamic"
DISABLED_ADAPTER_TYPE = "hostonly"
ALLOWED_ADAPTER_TYPES = ("hostonly", "intnet", "none")

DESCRIPTION = f"""Print the status of all internet adapters of all VMs in VirtualBox.
Optionally, if any VM with {DYNAMIC_VM_NAME} in the name has an adapter whose type is not allowed,
send a notification and change the type of the adapters with non-allowed type to {DISABLED_ADAPTER_TYPE}.
This is useful to detect internet access which is undesirable for dynamic malware analysis."""


EPILOG = textwrap.dedent(
    f"""
    Example usage:
      # Print status of all interfaces. For the VMs whose name contain {DYNAMIC_VM_NAME},
      # show a notification and disable internet if enabled.
      vbox-adapter-check.vm

      # For the VMs whose name contain {DYNAMIC_VM_NAME}, print the status of their interfaces.
      # If internet is enabled, show a notification and disable internet.
      vbox-adapter-check.vm --dynamic_only

      # Print status of all interfaces without modifying any of them.
      vbox-adapter-check.vm --do_not_modify

      # Print status of all interfaces in VMs whose name contain {DYNAMIC_VM_NAME} without modifying any of them.
      vbox-adapter-check.vm --dynamic_only --do_not_modify
    """
)


def get_vms(dynamic_only):
    """Get the names and UUID of the VirtualBox VMs using 'VBoxManage list vms'.

    Args:
        dynamic_only: If true, only the VMs containing DYNAMIC_VM_NAME in the name are returned.

    Returns:
        A list of tuples, where each tuple contains the VM name (str) and VM UUID (str).
        Returns an empty list if no VMs are found.
    """
    vms_list = []
    # regex VM name and extract the GUID
    # Example of `VBoxManage list vms` output:
    # "FLARE-VM.testing" {b76d628b-737f-40a3-9a16-c5f66ad2cfcc}
    # "FLARE-VM" {a23c0c37-2062-4cf0-882b-9e9747dd33b6}
    vms_info = run_vboxmanage(["list", "vms"])

    vms = re.findall(r'"(.*?)" (\{.*?\})', vms_info)
    for vm_name, vm_uuid in vms:
        # Get only the VMs containing DYNAMIC_VM_NAME in the name if dynamic_only is true
        if not (dynamic_only and (DYNAMIC_VM_NAME in vm_name)):
            vms_list.append((vm_name, vm_uuid))
    return vms_list


def get_nics(vm_uuid, only_nic=None):
    """
    Retrieves the configured network interfaces and their types for a given virtual machine.

    Args:
        vm_uuid: The unique identifier (UUID) of the virtual machine.
        only_nic: An optional string specifying a specific NIC number to retrieve
                  (e.g., "1" for nic1). If None, information for all configured NICs
                  will be returned.

    Returns:
        A list of tuples, where each tuple contains:
        - The NIC number as a string (e.g., "1", "2")
        - The NIC value (e.g., "hostonly", "nat")
    """

    # Example of `VBoxManage showvm_info <VM_UUID> --machinereadable` relevant output:
    # nic1="hostonly"
    # nictype1="82540EM"
    # nicspeed1="0"
    # nic2="none"
    # nic3="none"
    # nic4="none"
    # nic5="none"
    # nic6="none"
    # nic7="none"
    # nic8="none"
    vm_info = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])

    # If no nic provided, get all possible numbers using RegExp
    only_nic = r"\d+"

    # Get adapters numbers and their values as a list: [(nic_number, nic_value)]
    return re.findall(rf'^nic({only_nic})="(\S+)"', vm_info, flags=re.M)


def disable_adapter(vm_uuid, nic_number, hostonly_ifname):
    """Disable the network adapter of the VM by setting it to DISABLED_ADAPTER_TYPE

    Args:
        vm_uuid: VM UUID
        nic_number: nic to disable

    Raises:
        RuntimeError: If the nic type is not changed to DISABLED_ADAPTER_TYPE
    """
    # We need to run a different command if the machine is running.
    if get_vm_state(vm_uuid) in ("poweroff", "aborted"):
        run_vboxmanage(
            [
                "modifyvm",
                vm_uuid,
                f"--nic{nic_number}",
                DISABLED_ADAPTER_TYPE,
            ]
        )
        # Set the hostonlyadapter for nic as "VBoxManage modifyvm --nic" does not set it
        # If hostonlyadapter is empty, starting the VM raises an error
        run_vboxmanage(
            [
                "modifyvm",
                vm_uuid,
                f"--hostonlyadapter{nic_number}",
                hostonly_ifname,
            ]
        )
    else:
        run_vboxmanage(
            [
                "controlvm",
                vm_uuid,
                f"nic{nic_number}",
                DISABLED_ADAPTER_TYPE,
                hostonly_ifname,
            ]
        )

    # Verify nic has been modify as the command may return code 0 even if it fails to set the adapter
    _, nic_value = get_nics(vm_uuid, nic_number)[0]
    if nic_value != DISABLED_ADAPTER_TYPE:
        raise RuntimeError(f"nic{nic_number} has type '{nic_value}'")


def list_to_str(string_list):
    """Joins a list of strings with ", "."""
    return ", ".join(string_list)


def verify_network_adapters(vm_uuid, vm_name, hostonly_ifname, modify_and_notify):
    """Verify and optionally correct network adapter configurations for a given VM.

    Check the network adapter types of a given VM against a list of allowed types (`ALLOWED_ADAPTER_TYPES`).
    If not allowed adapter types are found, print a warning and, if `do_not_modify` is False, disable the adapters and sends a desktop notification.

    Args:
        vm_uuid: The unique identifier (UUID) of the VM.
        vm_name: The name of the VM.
        hostonly_ifname: The name of the host-only network interface. This is passed for potential use in
                         disabling adapters (though not directly used in the verification logic).
        modify_and_notify: A boolean flag. If False, invalid adapters will only be reported, without automatic modification and notification.
    """
    try:
        invalid_nics = []
        for nic_number, nic_value in get_nics(vm_uuid):
            if nic_value not in ALLOWED_ADAPTER_TYPES:
                invalid_nics.append(nic_number)

        if not invalid_nics:
            print(f"VM {vm_uuid} ✅ {vm_name} network configuration is ok")
            return

        invalid_nics_msg = list_to_str(invalid_nics)
        print(f"VM {vm_uuid} ⚠️  {vm_name} is connected to the internet on adapter(s): {invalid_nics_msg}")

        if modify_and_notify:
            # Disable invalid nics
            for nic in invalid_nics:
                try:
                    disable_adapter(vm_uuid, nic, hostonly_ifname)
                    print(f"VM {vm_uuid} ⚙️  {vm_name} set adapter {nic} to {DISABLED_ADAPTER_TYPE}")
                except Exception as e:
                    print(f"VM {vm_uuid} ❌ {vm_name} unable to disable adapter {nic}: {e}")

            message = (
                f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}."
                "The network adapter(s) may have been disabled automatically to prevent an undesired internet connectivity."
                "Please double check your VMs settings."
            )
            # Show notification using PyGObject
            Notify.init("VirtualBox adapter check")
            notification = Notify.Notification.new(f"⚠️  INTERNET IN VM: {vm_name}", message, "dialog-error")
            # Set highest priority
            notification.set_urgency(2)
            notification.show()

    except Exception as e:
        print(f"VM {vm_uuid} {vm_name} ❌ Unable to verify network adapters: {e}")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--do_not_modify",
        action="store_true",
        help="Only print the status of the internet adapters without modifying them and without showing a notification.",
    )
    parser.add_argument(
        "--dynamic_only",
        action="store_true",
        help="Only scan VMs with .dynamic in the name",
    )
    args = parser.parse_args(args=argv)

    hostonly_ifname = ensure_hostonlyif_exists()
    vms = get_vms(args.dynamic_only)
    if len(vms) > 0:
        for vm_name, vm_uuid in vms:
            # Never modify VMs without DYNAMIC_VM_NAME in the name (only check the status)
            modify_and_notify = (DYNAMIC_VM_NAME in vm_name) and (not args.do_not_modify)
            verify_network_adapters(vm_uuid, vm_name, hostonly_ifname, modify_and_notify)
    else:
        print("⚠️  No VMs found!")


if __name__ == "__main__":
    main()
