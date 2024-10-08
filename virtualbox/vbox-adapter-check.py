#!/usr/bin/python3

import argparse
import re
import sys
import textwrap

import gi

gi.require_version("Notify", "0.7")
from gi.repository import Notify

from vboxcommon import *

DYNAMIC_VM_NAME = ".dynamic"
DISABLED_ADAPTER_TYPE = "hostonly"
ALLOWED_ADAPTER_TYPES = ("hostonly", "intnet", "none")


def get_vm_uuids(dynamic_only):
    """Gets the machine UUID(s) for a given VM name using 'VBoxManage list vms'."""
    machine_guids = []
    try:
        # regex VM name and extract the GUID
        # "FLARE-VM.testing" {b76d628b-737f-40a3-9a16-c5f66ad2cfcc}
        vms_output = run_vboxmanage(["list", "vms"])
        pattern = r'"(.*?)" \{(.*?)\}'
        matches = re.findall(pattern, vms_output)
        for match in matches:
            vm_name = match[0]
            machine_guid = match[1]
            # either get all vms if dynamic_only false, or just the dynamic vms if true
            if (not dynamic_only) or DYNAMIC_VM_NAME in vm_name:
                machine_guids.append((vm_name, machine_guid))
    except Exception as e:
        raise Exception(f"Error finding machines UUIDs") from e
    return machine_guids


def change_network_adapters_to_hostonly(
    machine_guid, vm_name, hostonly_ifname, do_not_modify
):
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

        vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
        for nic_number, nic_value in re.findall(
            '^nic(\d+)="(\S+)"', vminfo, flags=re.M
        ):
            if nic_value not in ALLOWED_ADAPTER_TYPES:
                nics_with_internet.append(f"nic{nic_number}")
                invalid_nics_msg += f"{nic_number} "

        # modify the invalid adapters if allowed
        if nics_with_internet:
            for nic in nics_with_internet:
                if do_not_modify:
                    message = f"{vm_name} may be connected to the internet on adapter(s): {nic}. Please double check your VMs settings."
                else:
                    message = f"{vm_name} may be connected to the internet on adapter(s): {nic}. The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity. Please double check your VMs settings."
                    # different commands are necessary if the machine is running.
                    if get_vm_state(machine_guid) == "poweroff":
                        run_vboxmanage(
                            [
                                "modifyvm",
                                machine_guid,
                                f"--{nic}",
                                DISABLED_ADAPTER_TYPE,
                            ]
                        )
                    else:
                        run_vboxmanage(
                            [
                                "controlvm",
                                machine_guid,
                                nic,
                                "hostonly",
                                hostonly_ifname,
                            ]
                        )
                    print(f"Set VM {vm_name} adaper {nic} to hostonly")

            if do_not_modify:
                message = f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}. Please double check your VMs settings."
            else:
                message = f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}. The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity. Please double check your VMs settings."

            # Show notification using PyGObject
            Notify.init("VirtualBox adapter check")
            notification = Notify.Notification.new(
                f"INTERNET IN VM: {vm_name}", message, "dialog-error"
            )
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

    epilog = textwrap.dedent(
        f"""
        Example usage:
          # Print status of all internet adapters and disable the adapters with internet access in VMs with {DYNAMIC_VM_NAME} in the name
          vbox-adapter-check.vm

          # Print status of all internet adapters without modifying any of them
          vbox-adapter-check.vm --do_not_modify
        """
    )
    parser = argparse.ArgumentParser(
        description=f"Print the status of all internet adapters of all VMs in VirtualBox. Notify if any VM with {DYNAMIC_VM_NAME} in the name has an adapter whose type is not allowed (internet access is undesirable for dynamic malware analysis)i. Optionally change the type of the adapters with non-allowed type to Host-Only.",
        epilog=epilog,
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
        machine_guids = get_vm_uuids(args.dynamic_only)
        if len(machine_guids) > 0:
            for vm_name, machine_guid in machine_guids:
                change_network_adapters_to_hostonly(
                    machine_guid, vm_name, hostonly_ifname, args.do_not_modify
                )
        else:
            print(f"[Warning ⚠️] No VMs found")
    except Exception as e:
        print(f"Error verifying dynamic VM hostonly configuration: {e}")


if __name__ == "__main__":
    main()
