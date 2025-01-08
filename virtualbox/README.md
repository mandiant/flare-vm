# VirtualBox scripts

**This folder contains several scripts related to enhance building, exporting, and using FLARE-VM in VirtualBox.**

## Export snapshots

[`vbox-export-snapshots.py`](vbox-export-snapshots.py) export one or more snapshots in the same VirtualBox virtual machine (VM) as `.ova`, changing the network adapter to Host-Only.
It also generates a file with the SHA256 hash of the exported `.ova`.
This script is useful to export several versions of FLARE-VM after its installation consistently and with the internet disabled by default (desired for malware analysis).
For example, you may want to export a VM with the default FLARE-VM configuration and another installing in addition the packages `visualstudio.vm` and `pdbs.pdbresym.vm`.
These packages are useful for malware analysis but are not included in the default configuration because of the consequent increase in size.


## Check internet adapter status

[`vbox-adapter-check.py`](vbox-adapter-check.py) prints the status of all internet adapters of all VMs in VirtualBox.
The script also notifies if any dynamic analysis VM (with `.dynamic` in the name) has an adapter whose type is not allowed (internet access is undesirable for dynamic malware analysis).
Unless the argument `--do_not_modify` is provided, the script changes the type of the adapters with non-allowed type to Host-Only.
Unless the argument `--skip_disabled` is provided, the script also explores the disabled adapters, printing their status and possibly changing their type.
The script has been tested in Debian 12 with GNOME 44.9.

### Example

```
$ ./vbox-adapter-check.py
windows10 1: Enabled  HostOnly
windows10 2: Disabled Null
windows10 3: Disabled Null
windows10 4: Disabled Null
windows10 5: Disabled Null
windows10 6: Disabled Null
windows10 7: Disabled Null
windows10 8: Disabled Null
FLARE-VM.20240808.dynamic 1: Enabled  NAT
FLARE-VM.20240808.dynamic 2: Disabled NAT
FLARE-VM.20240808.dynamic 3: Disabled Bridged
FLARE-VM.20240808.dynamic 4: Enabled  Internal
FLARE-VM.20240808.dynamic 5: Disabled Null
FLARE-VM.20240808.dynamic 6: Disabled Null
FLARE-VM.20240808.dynamic 7: Disabled Null
FLARE-VM.20240808.dynamic 8: Disabled Null
```

#### Notification

![Notification](../Images/vbox-adapter-check_notification.png)


## Clean up snapshots

It is not possible to select and delete several snapshots in VirtualBox, making cleaning up your VM manually after having creating a lot snapshots time consuming and tedious (possible errors when deleting several snapshots simultaneously).

[`vbox-clean-snapshots.py`](vbox-clean-snapshots.py) cleans a VirtualBox VM up by deleting a snapshot and its children recursively skipping snapshots with a substring in the name.

### Example

```
$ ./vbox-remove-snapshots.py FLARE-VM.20240604

Cleaning FLARE-VM.20240604 🫧 Snapshots to delete:
  Snapshot 1
  wip unpacked
  JS downloader deobfuscated 
  Snapshot 6
  C2 decoded
  Snapshot 5
  wip
  Snapshot 4
  Snapshot 3
  Snapshot 2
  complicated chain - all samples ready

VM state: Paused
⚠️  Snapshot deleting is slower in a running VM and may fail in a changing state

Confirm deletion (press 'y'):y

Deleting... (this may take some time, go for an 🍦!)
  🫧 DELETED 'Snapshot 1'
  🫧 DELETED 'wip unpacked'
  🫧 DELETED 'JS downloader deobfuscated '
  🫧 DELETED 'Snapshot 6'
  🫧 DELETED 'C2 decoded'
  🫧 DELETED 'Snapshot 5'
  🫧 DELETED 'wip'
  🫧 DELETED 'Snapshot 4'
  🫧 DELETED 'Snapshot 3'
  🫧 DELETED 'Snapshot 2'
  🫧 DELETED 'complicated chain - all samples ready'

See you next time you need to clean up your VMs! ✨

```

##### Before


![Before](../Images/vbox-clean-snapshots_before.png)

##### After

![After](../Images/vbox-clean-snapshots_after.png)
