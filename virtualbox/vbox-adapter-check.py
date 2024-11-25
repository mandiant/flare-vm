#!/usr/bin/python3

import sys
import textwrap
import argparse
import subprocess
import re
import time
import gi
gi.require_version('Notify', '0.7')
from gi.repository import Notify

DYNAMIC_VM_NAME = '.dynamic'
DISABLED_ADAPTER_TYPE = "hostonly"
ALLOWED_ADAPTER_TYPES = ("hostonly", "intnet", "none")

# cmd is an array of string arguments to pass
def run_vboxmanage(cmd):
    """Runs a VBoxManage command and returns the output."""
    try:
        result = subprocess.run(["VBoxManage"] + cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error running VBoxManage command: {e}")

def get_vm_state(machine_guid):
    """Gets the VM state using 'VBoxManage showvminfo'."""
    vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
    for line in vminfo.splitlines():
        if line.startswith("VMState"):
            return line.split("=")[1].strip('"')
    raise Exception(f"Could not start VM '{machine_guid}'")

def ensure_hostonlyif_exists():
    """Gets the name of, or creates a new hostonlyif"""
    try:
        # Find existing hostonlyif
        hostonlyifs_output = run_vboxmanage(["list", "hostonlyifs"])
        for line in hostonlyifs_output.splitlines():
            if line.startswith("Name:"):
                hostonlyif_name = line.split(":")[1].strip()
                print(f"Found existing hostonlyif {hostonlyif_name}")
                return hostonlyif_name
        
        # No host-only interface found, create one
        print("No host-only interface found. Creating one...")
        run_vboxmanage(["hostonlyif", "create"])  # Create a host-only interface
        hostonlyifs_output = run_vboxmanage(["list", "hostonlyifs"])  # Get the updated list
        for line in hostonlyifs_output.splitlines():
            if line.startswith("Name:"):
                hostonlyif_name = line.split(":")[1].strip()
                print(f"Created hostonlyif {hostonlyif_name}")
                return hostonlyif_name
        print("Failed to create new hostonlyif. Exiting...")
        raise Exception("Failed to create new hostonlyif.")
    except Exception as e:
        print(f"Error getting host-only interface name: {e}")
    raise Exception("Failed to verify host-only interface exists")

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
        if vm_state == "saved":
            print(f"VM {machine_guid} is in a saved state. Powering on for a while then shutting down...")
            ensure_vm_running(machine_guid)
            time.sleep(120) # 2 minutes to boot up

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

def get_vm_uuids(dynamic_only):
    """Gets the machine UUID(s) for a given VM name using 'VBoxManage list vms'."""
    machine_guids = []
    try:
        vms_output = run_vboxmanage(["list", "vms"])
        pattern = r'"(.*?)" \{(.*?)\}'
        matches = re.findall(pattern, vms_output)
        if matches:
            for match in matches:
                vm_name = match[0]
                machine_guid = match[1]
                if dynamic_only and DYNAMIC_VM_NAME in vm_name:
                    machine_guids.append((vm_name, machine_guid))
                else:
                    machine_guids.append((vm_name, machine_guid))
    except Exception as e:
        raise Exception(f"Error finding machines UUIDs: {e}")
    return machine_guids

def change_network_adapters_to_hostonly(machine_guid, vm_name, hostonly_ifname, do_not_modify):
    """Verify all adapters are in an allowed configuration. Must be poweredoff"""
    try:
        # gather adapters in incorrect configurations
        nics_with_internet = []
        invalid_nics_msg = ''
        vminfo = run_vboxmanage(["showvminfo", machine_guid, "--machinereadable"])
        for nic_number, nic_value in re.findall("^nic(\d+)=\"(\S+)\"", vminfo, flags=re.M):
            if nic_value not in ALLOWED_ADAPTER_TYPES:
                nics_with_internet.append(f"nic{nic_number}")
                invalid_nics_msg += f'{nic_number} '

        # modify the invalid adapters if allowed
        if nics_with_internet:
            for nic in nics_with_internet:
                if do_not_modify:
                    message = f"{vm_name} may be connected to the internet on adapter(s): {nic}. Please double check your VMs settings."
                else:
                    message = f"{vm_name} may be connected to the internet on adapter(s): {nic}. The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity. Please double check your VMs settings."
                    # different commands are necessary if the machine is running.
                    if get_vm_state(machine_guid) == "poweroff":
                        run_vboxmanage(["modifyvm", machine_guid, f"--{nic}", DISABLED_ADAPTER_TYPE])
                        print(f"Set VM {nic} to hostonly")
                    else:
                        run_vboxmanage(["controlvm", machine_guid, nic, "hostonly", hostonly_ifname])
                        print(f"Set VM {nic} to hostonly")

            if do_not_modify:
                message = f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}. Please double check your VMs settings."
            else:
                message = f"{vm_name} may be connected to the internet on adapter(s): {invalid_nics_msg}. The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity. Please double check your VMs settings."
            
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
        print(f"Error changing network adapters: {e}")
    raise Exception("Failed to verify VM adapter configuration")

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
    parser.add_argument("--do_not_modify", action="store_true", help="Only print the status of the internet adapters without modifying them.")
    parser.add_argument("--dynamic_only", action="store_true", help="Only scan VMs with .dynamic in the name")
    args = parser.parse_args(args=argv)

    try:
        hostonly_ifname = ensure_hostonlyif_exists()
        machine_guids = get_vm_uuids(args.dynamic_only)
        if len(machine_guids) > 0:
            for vm_name, machine_guid in machine_guids:
                change_network_adapters_to_hostonly(machine_guid, vm_name, hostonly_ifname, args.do_not_modify)
        else:
            print(f"[Warning ⚠️] No VMs found")
    except Exception as e:
        print(f"Error verifying dynamic VM hostonly configuration: {e}")

if __name__ == "__main__":
    main()