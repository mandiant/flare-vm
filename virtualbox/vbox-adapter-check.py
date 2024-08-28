#!/usr/bin/python3

import sys
import textwrap
import argparse
import virtualbox
from virtualbox.library import NetworkAttachmentType as NetType
from gi.repository import Notify

DYNAMIC_VM_NAME = '.dynamic'
DISABLED_ADAPTER_TYPE = NetType.host_only
ALLOWED_ADAPTER_TYPES = (NetType.host_only, NetType.internal, NetType.null)

ENABLED_STRS = ('Disabled','Enabled ')

def check_and_disable_internet_access(session, machine_name, max_adapters, skip_disabled, do_not_modify):
    """
    Checks if a VM's network adapter is set to an internet-accessible mode
    and disables it if necessary, showing a warning popup.

    Args:
        session: The session of the virtual machine to check.
    """
    adapters_with_internet = []
    for i in range(max_adapters):
        adapter = session.machine.get_network_adapter(i)

        if skip_disabled and not adapter.enabled:
            continue

        print(f"{machine_name} {i+1}: {ENABLED_STRS[adapter.enabled]} {adapter.attachment_type}")

        if DYNAMIC_VM_NAME in machine_name and adapter.attachment_type not in ALLOWED_ADAPTER_TYPES:
            adapters_with_internet.append(i)
            if not do_not_modify:
                # Disable the adapter
                adapter.attachment_type = DISABLED_ADAPTER_TYPE

    if adapters_with_internet:
        adapters_str = ", ".join(str(i+1) for i in adapters_with_internet)
        if do_not_modify:
            message = f"{machine_name} may be connected to the internet on adapter(s): {adapters_str}. Please double check your VMs settings."
        else:
            message = f"{machine_name} may be connected to the internet on adapter(s): {adapters_str}. The network adapter(s) have been disabled automatically to prevent an undesired internet connectivity. Please double check your VMs settings."

        # Show notification using PyGObject
        Notify.init("VirtualBox adapter check")
        notification = Notify.Notification.new(f"INTERNET IN VM: {machine_name}", message, "dialog-error")
        # Set highest priority
        notification.set_urgency(2)
        notification.show()

    session.machine.save_settings()
    session.unlock_machine()


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

          # Print status of enabled internet adapters and disabled the enabled adapters with internet access in VMs with {DYNAMIC_VM_NAME} in the name
          vbox-adapter-check.vm --skip_disabled

          # # Print status of enabled internet adapters without modifying any of them
          vbox-adapter-check.vm --skip_disabled --do_not_modify
        """
    )
    parser = argparse.ArgumentParser(
        description=f"Print the status of all internet adapters of all VMs in VirtualBox. Notify if any VM with {DYNAMIC_VM_NAME} in the name has an adapter whose type is not allowed (internet access is undesirable for dynamic malware analysis)i. Optionally change the type of the adapters with non-allowed type to Host-Only.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--do_not_modify", action="store_true", help="Only print the status of the internet adapters without modifying them.")
    parser.add_argument("--skip_disabled", action="store_true", help="Skip the disabled adapters.")
    args = parser.parse_args(args=argv)

    vbox = virtualbox.VirtualBox()
    for machine in vbox.machines:
        session = machine.create_session()
        max_adapters = vbox.system_properties.get_max_network_adapters(machine.chipset_type)
        check_and_disable_internet_access(session, machine.name, max_adapters, args.skip_disabled, args.do_not_modify)


if __name__ == "__main__":
    main()
