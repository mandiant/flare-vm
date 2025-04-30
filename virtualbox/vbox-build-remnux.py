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
import sys
from datetime import datetime

import yaml
from vboxcommon import (
    control_guest,
    ensure_vm_running,
    export_vm,
    get_vm_uuid,
    restore_snapshot,
    set_network_to_hostonly,
    take_snapshot,
)

DESCRIPTION = """
Automates the creation and export of customized REMnux virtual machines (VMs).
Begins by restoring a pre-existing "BUILD-READY" snapshot of a clean REMnux OVA.
Required installation files (such as the IDA Pro installer and ZIPs with GNOME extensions) are then copied into the guest VM.
The configuration file specifies the VM name, the exported VM name, and details for each snapshot.
Individual snapshot configurations include the extension, description, and custom commands to be executed within the guest.
"""

EPILOG = """
Example usage:
  #./vbox-build-remnux.py configs/remnux.yaml --date='19930906'
"""

BASE_SNAPSHOT = "BUILD-READY"

# Guest username and password, needed to execute commands in the guest
GUEST_USERNAME = "remnux"
GUEST_PASSWORD = "malware"

# Required files
REQUIRED_FILES_DIR = os.path.expanduser("~/REMNUX REQUIRED FILES")
REQUIRED_FILES_DEST = rf"/home/{GUEST_USERNAME}/Desktop"


def run_command(vm_uuid, cmd):
    """Run a command in the guest of the specified VM, displaying the output in real time to the console.

    Args:
        vm_uuid: VM UUID
        cmd: The command string to execute in the guest using `/bin/sh -c`.
    """
    ensure_vm_running(vm_uuid)

    executable = "/bin/sh"
    print(f"VM {vm_uuid} 🚧 {executable}: {cmd}")
    control_guest(vm_uuid, GUEST_USERNAME, GUEST_PASSWORD, ["run", executable, "--", "-c", cmd], True)


def build_vm(vm_name, exported_vm_name, snapshot, cmds, date, do_not_upgrade):
    """
    Build a REMnux VM and export it as OVA.

    Build a REMnux VM by restoring the BASE_SNAPSHOT, upgrading the REMnux distro,
    copying required files, running given commands, removing copied required files.
    Take several snapshots that can be used for debugging issues.
    Set the network to hostonly and export the resulting VM as OVA.

    Args:
        vm_name: The name of the VM.
        exported_vm_name: The base name to use for the final exported VM and snapshots.
        snapshot: A dictionary containing information about the final snapshot,
                  including optional `extension` and `description`.
        cmds: A list of string commands to execute sequentially within the guest VM.
              A snapshot is taken after executing each command.
        date: A date string to incorporate into snapshot names and the exported OVA.
        do_not_upgrade: If True, the initial upgrade step is skipped and an existent UPGRADED snapshot used.
                        It also does not copy the required files.
    """
    vm_uuid = get_vm_uuid(vm_name)
    if not vm_uuid:
        print(f'❌ ERROR: "{vm_name}" not found')
        exit()

    print(f'\nGetting the installation VM "{vm_name}" {vm_uuid} ready...')

    base_snapshot_name = f"UPGRADED.{date}"

    if not do_not_upgrade:
        restore_snapshot(vm_uuid, BASE_SNAPSHOT)

        # Copy required files
        control_guest(
            vm_uuid,
            GUEST_USERNAME,
            GUEST_PASSWORD,
            ["copyto", "--recursive", f"--target-directory={REQUIRED_FILES_DEST}", REQUIRED_FILES_DIR],
        )
        print(f"VM {vm_uuid} 📁 Copied required files in: {REQUIRED_FILES_DIR}")

        # Update REMnux distro and take a snapshot
        run_command(vm_uuid, "sudo remnux upgrade")
        take_snapshot(vm_uuid, base_snapshot_name)
    else:
        restore_snapshot(vm_uuid, base_snapshot_name)

    # Run snapshot configured commands taking a snapshot after running every command
    for i, cmd in enumerate(cmds):
        run_command(vm_uuid, cmd)
        take_snapshot(vm_uuid, f"{exported_vm_name}.{date} CMD {cmd.splitlines()[0]}")

    # Delete required files copied to the VM
    files = f"{REQUIRED_FILES_DEST}/*"
    # Sync is needed ti ensure the files deletion is written to persistent storage as the script shut down the VM abruptly
    run_command(vm_uuid, f"ls {files}; rm {files}; sync")

    set_network_to_hostonly(vm_uuid)

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
        "--do-not-upgrade",
        action="store_true",
        default=False,
        help="flag to not upgrade the REMnux distro and use an existent UPGRADED snapshot. It also does not copy the required files.",
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
        config["SNAPSHOT"],
        config["CMDS"],
        args.date,
        args.do_not_upgrade,
    )


if __name__ == "__main__":
    main()
