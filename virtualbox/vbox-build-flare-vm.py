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
import os
import re
import sys
import time
from datetime import datetime

import yaml
from vboxcommon import (
    LONG_WAIT,
    ensure_vm_running,
    ensure_vm_shutdown,
    export_vm,
    get_vm_state,
    get_vm_uuid,
    restore_snapshot,
    run_vboxmanage,
    set_network_to_hostonly,
)

DESCRIPTION = """
Automates the creation and export of customized FLARE-VM virtual machines (VMs).
Begins by restoring a pre-existing "BUILD-READY" snapshot of a clean Windows installation (with UAC disabled).
Required installation files (such as the IDA Pro installer, FLARE-VM configuration, and legal notices) are then copied into the guest VM.
After installing FLARE-VM, a "base" snapshot is taken.
This snapshot serves as the foundation for generating subsequent snapshots and exporting OVA images,
all based on the configuration provided in a YAML file.
This configuration file specifies the VM name, the exported VM name, and details for each snapshot.
Individual snapshot configurations can include custom commands to be executed within the guest, legal notices to be applied,
and file/folder exclusions for the automated cleanup process.
"""

EPILOG = """
Example usage:
  # Build FLARE-VM and export several OVAs using the information in the provided configuration file, using '19930906' as date
  #./vbox-build-vm.py configs/win10_flare-vm.yaml --custom_config --date='19930906'
"""

# The base snapshot is expected to be an empty Windows installation that satisfies the FLARE-VM installation requirements and has UAC disabled
# To disable UAC execute in a cmd console with admin rights and restart the VM for the change to take effect:
# %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
BASE_SNAPSHOT = "BUILD-READY"

# Guest username and password, needed to execute commands in the guest
GUEST_USERNAME = "flare"
GUEST_PASSWORD = "password"

# Logs
LOGS_DIR = os.path.expanduser("~/FLARE-VM LOGS")
LOG_FILE_GUEST = r"C:\ProgramData\_VM\log.txt"
LOG_FILE_HOST = rf"{LOGS_DIR}/flare-vm-log.txt"
FAILED_PACKAGES_GUEST = r"C:\ProgramData\_VM\failed_packages.txt"
FAILED_PACKAGES_HOST = rf"{LOGS_DIR}/flare-vm-failed_packages.txt"

# Required files
REQUIRED_FILES_DIR = os.path.expanduser("~/FLARE-VM REQUIRED FILES")
REQUIRED_FILES_DEST = rf"C:\Users\{GUEST_USERNAME}\Desktop"

# Executable paths in guest
POWERSHELL_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD_PATH = r"C:\Windows\System32\cmd.exe"

# Cleanup command to be executed in cmd to delete the PowerShel logs
CMD_CLEANUP_CMD = r"/C rmdir /s /q %UserProfile%\Desktop\PS_Transcripts && start timeout 3"


def control_guest(vm_uuid, args, real_time=False):
    """Run a 'VBoxManage guestcontrol' command providing the username and password.
    Args:
        vm_uuid: VM UUID
        args: list of arguments starting with the guestcontrol sub-command
        real_time: Boolean that determines if displaying the output in realtime or returning it.
    """
    # VM must be running to control the guest
    ensure_vm_running(vm_uuid)
    cmd = ["guestcontrol", vm_uuid, f"--username={GUEST_USERNAME}", f"--password={GUEST_PASSWORD}"] + args
    try:
        return run_vboxmanage(cmd, real_time)
    except RuntimeError:
        # The guest additions take a bit to load after the user is logged in
        # In slow environments this may cause the command to fail, wait a bit and re-try
        time.sleep(120)  # Wait 2 minutes
        return run_vboxmanage(cmd, real_time)


def run_command(vm_uuid, cmd, executable="PS"):
    """Run a command in the guest displaying the output in real time."""
    ensure_vm_running(vm_uuid)

    exe_path = POWERSHELL_PATH if executable == "PS" else CMD_PATH

    print(f"VM {vm_uuid} 🚧 {executable}: {cmd}")
    control_guest(vm_uuid, ["run", exe_path, cmd], True)


def take_snapshot(vm_uuid, snapshot_name, shutdown=False):
    """Take a snapshot with the given name in the given VM, optionally shutting down the VM before."""
    if shutdown:
        ensure_vm_shutdown(vm_uuid)

    # Take a base snapshot, ensuring there is no snapshot with the same name
    rename_old_snapshot(vm_uuid, snapshot_name)
    run_vboxmanage(["snapshot", vm_uuid, "take", snapshot_name])
    print(f'VM {vm_uuid} 📷 took snapshot "{snapshot_name}"')


def create_log_folder():
    """Ensure log folder exists and is empty."""
    # Create directory if it does not exist
    os.makedirs(LOGS_DIR, exist_ok=True)
    print(f"Log folder: {LOGS_DIR}\n")

    # Remove all files in the logs directory. Note the directory only files (the logs).
    for file_name in os.listdir(LOGS_DIR):
        file_path = os.path.join(LOGS_DIR, file_name)
        os.remove(file_path)


def install_flare_vm(vm_uuid, snapshot_name, custom_config):
    """Install FLARE-VM"""
    additional_arg = r"-customConfig '$desktop\config.xml'" if custom_config else ""
    flare_vm_installation_cmd = rf"""
    $desktop=[Environment]::GetFolderPath("Desktop")
    cd $desktop
    Set-ExecutionPolicy Unrestricted -Force
    $url="https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1"
    $file = "$desktop\install.ps1"
    (New-Object net.webclient).DownloadFile($url,$file)
    Unblock-File .\install.ps1

    start powershell "$file -password password -noWait -noGui -noChecks {additional_arg}"
    """
    run_command(vm_uuid, flare_vm_installation_cmd)
    print(f"VM {vm_uuid} ✅ FLARE-VM is being installed...{LONG_WAIT}")

    index = 0
    while True:
        time.sleep(120)  # Wait 2 minutes
        try:
            control_guest(vm_uuid, ["copyfrom", f"--target-directory={FAILED_PACKAGES_HOST}", FAILED_PACKAGES_GUEST])
            break
        except RuntimeError:
            index += 1
            if (index % 10) == 0:  # Print an "I am alive" message every ~20 minutes
                time_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                print(f"VM {vm_uuid} 🕑 {time_str} still waiting")
                # Take snaphost that can be restore if the VM crashes
                # Avoid taking a snapshot during a restart (as it could crash the VM) by checking the VM is running
                if get_vm_state(vm_uuid) == "running":
                    wip_snapshot_name = f"WIP {snapshot_name} {time_str}"
                    take_snapshot(vm_uuid, wip_snapshot_name)

    print(f"VM {vm_uuid} ✅ FLARE-VM installed!")

    control_guest(vm_uuid, ["copyfrom", f"--target-directory={LOG_FILE_HOST}", LOG_FILE_GUEST])
    print(f"VM {vm_uuid} 📁 Copied FLARE-VM log: {REQUIRED_FILES_DIR}")

    # Read failed packages from log file and print them
    try:
        if os.path.getsize(FAILED_PACKAGES_HOST):
            print("  ❌ FAILED PACKAGES")
            with open(FAILED_PACKAGES_HOST, "r") as f:
                for failed_package in f:
                    print(f"     - {failed_package}")
    except Exception:
        print(f"  ❌ Reading {FAILED_PACKAGES_HOST} failed")


def rename_old_snapshot(vm_uuid, snapshot_name):
    """Append 'OLD' to the name of the snapshots with the given name"""
    # Example of 'VBoxManage snapshot VM_NAME list --machinereadable' output:
    # SnapshotName="ROOT"
    # SnapshotUUID="86b38fc9-9d68-4e4b-a033-4075002ab570"
    # SnapshotName-1="Snapshot 1"
    # SnapshotUUID-1="e383e702-fee3-4e0b-b1e0-f3b869dbcaea"
    snapshots_info = run_vboxmanage(["snapshot", vm_uuid, "list", "--machinereadable"])

    # Find how many snapshots have the given name and edit a snapshot with that name as many times
    snapshots = re.findall(rf'^SnapshotName(-\d+)*="{snapshot_name}"\n', snapshots_info, flags=re.M)
    for _ in range(len(snapshots)):
        run_vboxmanage(["snapshot", vm_uuid, "edit", snapshot_name, f"--name='{snapshot_name} OLD"])


def build_vm(vm_name, exported_vm_name, snapshots, date, custom_config, do_not_install_flare_vm):
    """"""
    vm_uuid = get_vm_uuid(vm_name)
    if not vm_uuid:
        print(f'❌ ERROR: "{vm_name}" not found')
        exit()

    print(f'\nGetting the installation VM "{vm_name}" {vm_uuid} ready...')
    create_log_folder()

    base_snapshot_name = f"{exported_vm_name}.{date}.base"

    if not do_not_install_flare_vm:
        restore_snapshot(vm_uuid, BASE_SNAPSHOT)

        control_guest(
            vm_uuid, ["copyto", "--recursive", f"--target-directory={REQUIRED_FILES_DEST}", REQUIRED_FILES_DIR]
        )
        print(f"VM {vm_uuid} 📁 Copied required files in: {REQUIRED_FILES_DIR}")

        install_flare_vm(vm_uuid, exported_vm_name, custom_config)
        take_snapshot(vm_uuid, base_snapshot_name)

    for snapshot in snapshots:
        restore_snapshot(vm_uuid, base_snapshot_name)

        # Run snapshot configured command
        cmd = snapshot.get("cmd", None)
        if cmd:
            run_command(vm_uuid, cmd)

        set_network_to_hostonly(vm_uuid)

        # Set snapshot configured legal notice
        notice_file_name = snapshot.get("legal_notice", None)
        if notice_file_name:
            notice_file_path = rf"C:\Users\{GUEST_USERNAME}\Desktop\{notice_file_name}"
            set_notice_cmd = f"VM-Set-Legal-Notice (Get-Content  '{notice_file_path}' -Raw)"
            run_command(vm_uuid, set_notice_cmd)

        # Perform clean up: run 'VM-Clean-Up' excluding configured files and folders
        ps_cleanup_cmd = "VM-Clean-Up"
        protected_files = snapshot.get("protected_files", None)
        if protected_files:
            ps_cleanup_cmd += f" -excludeFiles {protected_files}"
        protected_folders = snapshot.get("protected_folders", None)
        if protected_folders:
            ps_cleanup_cmd += f" -excludeFolders {protected_folders}"
        run_command(vm_uuid, ps_cleanup_cmd)

        # Perform clean up: delete PowerShells logs (using cmd.exe)
        run_command(vm_uuid, CMD_CLEANUP_CMD, "CMD")

        # Take snapshot turning the VM off
        extension = snapshot.get("extension", "")
        snapshot_name = f"{exported_vm_name}.{date}{extension}"
        take_snapshot(vm_uuid, snapshot_name, True)

        # Export the snapshot with the configured description
        export_vm(vm_uuid, snapshot_name, snapshot.get("description", ""))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("config_path", help="path of the YAML configuration file.")
    parser.add_argument(
        "--date",
        help="Date to include in the snapshots and the exported VMs in YYYYMMDD format. Today's date by default.",
        default=datetime.today().strftime("%Y%m%d"),
    )
    parser.add_argument(
        "--custom_config",
        action="store_true",
        default=False,
        help=f"flag to use a custom configuration file named 'config.xml' (expected to be in {REQUIRED_FILES_DIR}) for the FLARE-VM installation.",
    )
    parser.add_argument(
        "--do-not-install-flare-vm",
        action="store_true",
        default=False,
        help="flag to not install FLARE-VM and used an existent base snapshot.",
    )
    args = parser.parse_args(args=argv)

    try:
        with open(args.config_path) as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f'Invalid "{args.config_path}": {e}')
        exit()

    build_vm(
        config["VM_NAME"],
        config["EXPORTED_VM_NAME"],
        config["SNAPSHOTS"],
        args.date,
        args.custom_config,
        args.do_not_install_flare_vm,
    )


if __name__ == "__main__":
    main()
