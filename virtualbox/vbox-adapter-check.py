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
Notify if any VM with {DYNAMIC_VM_NAME} in the name has an adapter whose type is not allowed.
This is useful to detect internet access which is undesirable for dynamic malware analysis.
Optionally change the type of the adapters with non-allowed type to Host-Only."""

EPILOG = textwrap.dedent(
    f"""
    Example usage:
      # Print status of all interfaces and disable internet access in VMs whose name contain {DYNAMIC_VM_NAME}
      vbox-adapter-check.vm

      # Print status of all interfaces without modifying any of them
      vbox-adapter-check.vm --do_not_modify
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


def disable_adapter(vm_uuid, nic_number, hostonly_ifname):
    """Disable the network adapter of the VM by setting it to DISABLED_ADAPTER_TYPE

    Args:
        vm_uuid: VM UUID
        nic_number: nic to disable
    """
    # We need to run a different command if the machine is running.
    if get_vm_state(vm_uuid) == "poweroff":
        run_vboxmanage(
            [
                "modifyvm",
                vm_uuid,
                f"--nic{nic_number}",
                DISABLED_ADAPTER_TYPE,
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


def change_network_adapters_to_hostonly(vm_uuid, vm_name, hostonly_ifname, do_not_modify):
    """Verify all adapters are in an allowed configuration. Must be poweredoff"""
    try:
        # gather adapters in incorrect configurations
        nics_with_internet = []
        invalid_nics_msg = ""

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

        vminfo = run_vboxmanage(["showvminfo", vm_uuid, "--machinereadable"])
        for nic_number, nic_value in re.findall(r'^nic(\d+)="(\S+)"', vminfo, flags=re.M):
            if nic_value not in ALLOWED_ADAPTER_TYPES:
                nics_with_internet.append(nic_number)
                invalid_nics_msg += f"{nic_number} "

        # modify the invalid adapters if allowed
        if nics_with_internet:
            for nic in nics_with_internet:
                if do_not_modify:
                    message = f"{vm_name} may be connected to the internet on adapter(s): {nic}. Please double check your VMs settings."
                else:
                    message = (
                        f"{vm_name} may be connected to the internet on adapter(s): {nic}."
                        "The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity."
                        "Please double check your VMs settings."
                    )
                    disable_adapter(vm_uuid, nic, hostonly_ifname)
                    print(f"Set VM {vm_name} adaper {nic} to hostonly")

            if do_not_modify:
                message = f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}. Please double check your VMs settings."
            else:
                message = (
                    f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}."
                    "The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity."
                    "Please double check your VMs settings."
                )

            # Show notification using PyGObject
            Notify.init("VirtualBox adapter check")
            notification = Notify.Notification.new(f"INTERNET IN VM: {vm_name}", message, "dialog-error")
            # Set highest priority
            notification.set_urgency(2)
            notification.show()
            print(f"{vm_name} network configuration not ok, sent notifaction")
            return
        else:
            print(f"{vm_name} network configuration is ok")
            return

    except Exception as e:
        raise Exception("Failed to verify VM adapter configuration") from e


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
        help="Only print the status of the internet adapters without modifying them.",
    )
    parser.add_argument(
        "--dynamic_only",
        action="store_true",
        help="Only scan VMs with .dynamic in the name",
    )
    args = parser.parse_args(args=argv)

    try:
        hostonly_ifname = ensure_hostonlyif_exists()
        vms = get_vms(args.dynamic_only)
        if len(vms) > 0:
            for vm_name, vm_uuid in vms:
                change_network_adapters_to_hostonly(vm_uuid, vm_name, hostonly_ifname, args.do_not_modify)
        else:
            print("[Warning ⚠️] No VMs found")
    except Exception as e:
        print(f"Error verifying dynamic VM hostonly configuration: {e}")


if __name__ == "__main__":
    main()
