#!/usr/bin/python3
# Copyright 2026 Google LLC
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
import sys

from vboxcommon import (
    ALLOWED_ADAPTER_TYPES,
    DYNAMIC_VM_NAME,
    ensure_hostonlyif_exists,
    get_nics,
    get_vm_uuid,
    set_nic,
)

DESCRIPTION = """Switch a VM's network with a single command, without requiring the VM to be shut down first.
'isolate' checks every NIC and fixes any that aren't hostonly/intnet/none, for use right before or while
running a sample. 'nat' switches NIC 1 to nat to temporarily restore internet access for setup/downloads."""

EPILOG = f"""
Example usage:
  # Cut network access right before or while running a sample
  ./vbox-set-network.py "FLARE-VM.testing" isolate

  # Temporarily restore internet on NIC 1 to install or update a tool
  ./vbox-set-network.py "FLARE-VM.testing" nat

Note: if the VM name contains "{DYNAMIC_VM_NAME}" and vbox-adapter-check.py runs periodically on this
host, it will detect a "nat" adapter on that VM and switch it back to hostonly.
"""


def set_network(vm_name, mode):
    """Resolve vm_name to a UUID and switch its network according to mode ('isolate' or 'nat')."""
    vm_uuid = get_vm_uuid(vm_name)
    if not vm_uuid:
        raise RuntimeError(f'VM "{vm_name}" not found')

    if mode == "isolate":
        hostonly_ifname = ensure_hostonlyif_exists()
        fixed = []
        for nic_number, nic_value in get_nics(vm_uuid):
            if nic_value not in ALLOWED_ADAPTER_TYPES:
                set_nic(vm_uuid, nic_number, "hostonly", hostonly_ifname)
                fixed.append(nic_number)

        still_unsafe = [n for n, v in get_nics(vm_uuid) if v not in ALLOWED_ADAPTER_TYPES]
        if still_unsafe:
            raise RuntimeError(f"VM {vm_uuid} still has unsafe adapter(s): {', '.join(still_unsafe)}")

        if fixed:
            print(f"VM {vm_uuid} ⚙️  {vm_name} isolated: adapter(s) {', '.join(fixed)} set to hostonly")
        else:
            print(f"VM {vm_uuid} ✅ {vm_name} already isolated")
    else:
        if DYNAMIC_VM_NAME in vm_name:
            print(
                f'⚠️  "{vm_name}" contains "{DYNAMIC_VM_NAME}": if vbox-adapter-check.py runs '
                "periodically on this host, it will switch this adapter back to hostonly."
            )

        set_nic(vm_uuid, "1", "nat")

        nic_info = get_nics(vm_uuid, only_nic="1")
        if not nic_info or nic_info[0][1] != "nat":
            raise RuntimeError(f"VM {vm_uuid} NIC 1 was not switched to nat")

        print(f"VM {vm_uuid} ⚙️  {vm_name} NIC 1 set to nat")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vm_name", help="name of the VM to change the network for.")
    parser.add_argument(
        "mode", choices=("isolate", "nat"), help="'isolate' for hostonly on every NIC, 'nat' for internet on NIC 1."
    )
    args = parser.parse_args(args=argv)

    set_network(args.vm_name, args.mode)


if __name__ == "__main__":
    main()
