import subprocess
import time


# cmd is an array of string arguments to pass
def run_vboxmanage(cmd):
    """Runs a VBoxManage command and returns the output."""
    try:
        result = subprocess.run(
            ["VBoxManage"] + cmd, capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error running VBoxManage command: {e} ({e.stderr})")


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


def get_vm_state(machine_guid):
    """Gets the VM state using 'VBoxManage showvminfo'."""
    # VMState="poweroff"
    # VMStateChangeTime="2025-01-02T16:31:51.000000000"

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
            print(
                f"VM {machine_guid} is not running (state: {vm_state}). Starting VM..."
            )
            run_vboxmanage(["startvm", machine_guid, "--type", "gui"])

            # Wait for VM to start (up to 1 minute)
            timeout = 60  # seconds
            check_interval = 5  # seconds
            start_time = time.time()
            while time.time() - start_time < timeout:
                vm_state = get_vm_state(machine_guid)
                if vm_state == "running":
                    print(f"VM {machine_guid} started.")
                    time.sleep(5)  # wait a bit to be careful and avoid any weird races
                    return
                print(f"Waiting for VM (state: {vm_state})")
                time.sleep(check_interval)
            print("Timeout waiting for VM to start. Exiting...")
            raise TimeoutError(
                f"VM did not start within the timeout period {timeout}s."
            )
        else:
            print("VM is already running.")
            return
    except Exception as e:
        raise Exception(f"Could not ensure '{machine_guid}' running") from e


def ensure_vm_shutdown(machine_guid):
    """Checks if the VM is running and shuts it down if it is."""
    try:
        vm_state = get_vm_state(machine_guid)
        if vm_state == "saved":
            print(
                f"VM {machine_guid} is in a saved state. Powering on for a while then shutting down..."
            )
            ensure_vm_running(machine_guid)
            time.sleep(120)  # 2 minutes to boot up

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
                    time.sleep(5)  # wait a bit to be careful and avoid any weird races
                    return
                time.sleep(check_interval)
            print("Timeout waiting for VM to shut down. Exiting...")
            raise TimeoutError("VM did not shut down within the timeout period.")
        else:
            print(f"VM {machine_guid} is already shut down (state: {vm_state}).")
            return
    except Exception as e:
        raise Exception(f"Could not ensure '{machine_guid}' shutdown") from e
