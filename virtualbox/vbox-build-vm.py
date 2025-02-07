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

"""
Restore a `BUILD-READY` snapshot, copy files required for the installation (like the IDA Pro installer and
the FLARE-VM configuration file) and start the FLARE-VM installation.
"""

import os

from vboxcommon import ensure_vm_running, get_vm_uuid, restore_snapshot, run_vboxmanage

VM_NAME = "FLARE-VM.testing"
# The base snapshot is expected to be an empty Windows installation that satisfies the FLARE-VM installation requirements and has UAC disabled
# To disable UAC execute in a cmd console with admin rights and restart the VM for the change to take effect:
# %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
BASE_SNAPSHOT = "BUILD-READY"
GUEST_USERNAME = "flare"
GUEST_PASSWORD = "password"
script_directory = os.path.dirname(os.path.realpath(__file__))
REQUIRED_FILES_DIR = os.path.expanduser("~/REQUIRED FILES")
REQUIRED_FILES_DEST = f"C:\\Users\\{GUEST_USERNAME}\\Desktop"
INSTALLATION_COMMAND = r"""
$desktop=[Environment]::GetFolderPath("Desktop")
cd $desktop
Set-ExecutionPolicy Unrestricted -Force
$url="https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1"
$file = "$desktop/install.ps1"
(New-Object net.webclient).DownloadFile($url,$file)
Unblock-File .\install.ps1

start powershell "$file -password password -noWait -noGui -noChecks"
"""


def control_guest(vm_uuid, args):
    """Run a 'VBoxManage guestcontrol' command providing the username and password.
    Args:
        vm_uuid: VM UUID
        args: list of arguments starting with the guestcontrol sub-command
    """
    run_vboxmanage(["guestcontrol", vm_uuid, f"--username={GUEST_USERNAME}", f"--password={GUEST_PASSWORD}"] + args)


vm_uuid = get_vm_uuid(VM_NAME)
if not vm_uuid:
    print(f'❌ ERROR: "{VM_NAME}" not found')
    exit()

print(f'\nGetting the installation VM "{VM_NAME}" {vm_uuid} ready...\n')

restore_snapshot(vm_uuid, BASE_SNAPSHOT)
ensure_vm_running(vm_uuid)

control_guest(vm_uuid, ["copyto", "--recursive", f"--target-directory={REQUIRED_FILES_DEST}", REQUIRED_FILES_DIR])
print(f"VM {vm_uuid} 📁 Copied required files in: {REQUIRED_FILES_DIR}")


control_guest(vm_uuid, ["run", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", INSTALLATION_COMMAND])

print(f"\nVM {vm_uuid} ✅ FLARE-VM is being installed... it will take some time,")
print("  Go for an 🍦 and enjoy FLARE-VM when you are back!")
