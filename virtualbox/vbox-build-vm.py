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


import os

import pyperclip
from vboxcommon import ensure_vm_running, get_vm_uuid, restore_snapshot, run_vboxmanage

VM_NAME = "FLARE-VM.testing"
BASE_SNAPSHOT = "BUILD-READY"
GUEST_USERNAME = "flare"
GUEST_PASSWORD = "password"
REQUIRED_FILES_DIR = os.path.expanduser("~/REQUIRED FILES")
REQUIRED_FILES_DEST = "C:\\Users\\flare\\Desktop"
INSTALLATION_COMMAND = r"""
$desktop=[Environment]::GetFolderPath("Desktop")
cd $desktop
Set-ExecutionPolicy Unrestricted -Force
$url="https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1"
(New-Object net.webclient).DownloadFile($url,"$desktop/install.ps1")
Unblock-File .\install.ps1
.\install.ps1 -password password -noWait -noGui -noChecks
"""

vm_uuid = get_vm_uuid(VM_NAME)
if not vm_uuid:
    print(f'❌ ERROR: "{VM_NAME}" not found')
    exit()

print(f'\nGetting the installation VM "{VM_NAME}" {vm_uuid} ready...\n')

restore_snapshot(vm_uuid, BASE_SNAPSHOT)
ensure_vm_running(vm_uuid)

run_vboxmanage(
    [
        "guestcontrol",
        vm_uuid,
        f"--username={GUEST_USERNAME}",
        f"--password={GUEST_PASSWORD}",
        "copyto",
        "--recursive",
        f"--target-directory={REQUIRED_FILES_DEST}",
        REQUIRED_FILES_DIR,
    ]
)

print(f"VM {vm_uuid} 📁 Required files copied")


print("\n🎀 READY TO BUILD FLARE-VM")
input("Press any key to copy installation command...")
pyperclip.copy(INSTALLATION_COMMAND)
print("✅ COPIED! Paste the copied installation command in a PowerShell console with admin rights to install FLARE-VM")
