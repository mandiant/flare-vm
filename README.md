
      ______ _               _____  ______   __      ____  __
     |  ____| |        /\   |  __ \|  ____|  \ \    / /  \/  |
     | |__  | |       /  \  | |__) | |__ _____\ \  / /| \  / |
     |  __| | |      / /\ \ |  _  /|  __|______\ \/ / | |\/| |
     | |    | |____ / ____ \| | \ \| |____      \  /  | |  | |
     |_|    |______/_/    \_\_|  \_\______|      \/   |_|  |_|

      ________________________________________________________
                           Developed by
	                   flarevm@fireeye.com
          FLARE (FireEye Labs Advanced Reverse Engineering)
      ________________________________________________________

<p align="center">
  <img width="300" height="300" src="flarevm.png?raw=true" alt="FLARE VM"/>
</p>

Welcome to FLARE VM - a fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing, etc.

Please see [https://www.fireeye.com/blog/threat-research/2018/11/flare-vm-update.html](https://www.fireeye.com/blog/threat-research/2018/11/flare-vm-update.html) for a blog on installing FLARE VM.

Updates
===========

## Version 3.0 Updates
FLARE VM version `3.0` now supports Windows 10. The installer has been tested on Windows 10 VMs provided by Microsoft below:
* Windows 10 with Microsoft Edge: [https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
* Windows 10 development environment: [https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

## Version 2.3 Updates
Chocolatey now requires PowerShell v3 (or higher) and .NET 4.0 (or higher) due to recent upgrades to TLS 1.2. Please ensure .NET 4+ and PowerShell v3+ are installed prior to attempting FLARE VM installation. Below are links to download .NET 4.5 and WMF 5.1 (PowerShell 5.1).

* .NET 4.5 [https://www.microsoft.com/en-us/download/details.aspx?id=30653](https://www.microsoft.com/en-us/download/details.aspx?id=30653)
* WMF 5.1 [https://www.microsoft.com/en-us/download/details.aspx?id=54616](https://www.microsoft.com/en-us/download/details.aspx?id=54616)

## Version 2.0 Updates
Starting with version `2.0`, FLARE VM has introduced **breaking changes** with previous versions. A fresh installation in a clean Virtual Machine is recommended.

Starting with version 2.0, FLARE VM uses the following environment variables:
  - `TOOL_LIST_DIR`: The default value is set to *`%PROGRAMDATA%`*`\Microsoft\Windows\Start Menu\Programs\FLARE`.
  - `TOOL_LIST_SHORTCUT`: The default value is set to *`%USERPROFILE%`*`\Desktop\FLARE.lnk`.

The installer script sets those environment variables automatically. If there are issues during installation, please verify that those environment variables are set correctly.

Installation
=======================

Requirements
------------
* 60 GB Hard Drive
  * Additional space needed after VM is downloaded/installed
* 2 GB RAM

## Windows 10 Installation

### Pre-installation Steps
* Download one of the VMs from the links provided above
  * Import the `.ovf` if necessary  
* Disable Windows Defender by following the procedures outlined at:
  * [https://www.howtogeek.com/howto/15788/how-to-uninstall-disable-and-remove-windows-defender-also-how-turn-it-off/](https://www.howtogeek.com/howto/15788/how-to-uninstall-disable-and-remove-windows-defender-also-how-turn-it-off/)
* Additionally make sure to disable the following settings:
  * Disable real-time protection
  * Disable cloud-delivered protection
  * Disable automatic sample submission
  * Add the directory `C:\` to the exclusion list
* Take a snapshot of your machine!

### Installations Steps
* Download and copy [install.ps1](https://github.com/fireeye/flare-vm/raw/master/install.ps1) onto your new VM
* Open `PowerShell` as an Administrator
* Unblock the install file by running:
  * `Unblock-File .\install.ps1`
* Enable script execution by running:
  * `Set-ExecutionPolicy Unrestricted`
* Finally, execute the installer script as follow:
  * `.\install.ps1`
  * You can also pass your password as an argument: `.\install.ps1 -password <password>`

### Post-installation Steps
* If the background was not successfully set:
  * Navigate to _`%PROGRAMDATA%`_`\chocolatey\lib\flarevm.win10.config.flare\tools` and right click `flarevm.png`
  * Right click `flarevm.png` and select `Set as desktop background`
* Update your VM's networking settings to `Host-Only`
* Make it yours!
  * Customize your taskbar with various shortcuts
  * Customize your color scheme
* Take a snapshot!

## Windows 7 x64 Installation

### Pre-Installations Steps
* Create and configure a new Windows Virtual Machine
  * FLARE VM is designed to be installed on Windows 7 Service Pack 1 or newer
  * Allow for a total of 50-60 GB disk storage (including OS)
  * Ensure VM is updated completely. You may have to check for updates, reboot, and check again until no more remain
* Install .NET 4.5 and WMF 5.1 from the following links:
  * .NET 4.5 [https://www.microsoft.com/en-us/download/details.aspx?id=30653](https://www.microsoft.com/en-us/download/details.aspx?id=30653)
  * WMF 5.1 [https://www.microsoft.com/en-us/download/details.aspx?id=54616](https://www.microsoft.com/en-us/download/details.aspx?id=54616)
  * Make sure you restart the VM to complete the installation
* Take a snapshot of your machine!

### Installation Steps
* Download and copy [install.ps1](https://github.com/fireeye/flare-vm/raw/master/install.ps1) onto your newly configured machine
* Open PowerShell as an Administrator
* Enable script execution by running the following command:
  * `Set-ExecutionPolicy Unrestricted`
* Finally, execute the installer script as follows:
  * `.\install.ps1`
  * You can also pass your password as an argument: `.\install.ps1 -password <password>`

### Post-installation Steps
* If the background was not successfully set:
  * Navigate to _`%PROGRAMDATA%`_`\chocolatey\lib\flarevm.config.flare\tools` and right click `flarevm.png`
  * Right click `flarevm.png` and select `Set as desktop background`
* Update your VM's networking settings to `Host-Only`
* Make it yours!
  * Customize your taskbar with various shortcuts
  * Customize your color scheme
* Take a snapshot!

Customized Package Selection
======================
You can now select which packages you wish to install!

* *NOTE*: By customizing your own packages list, you will NOT automatically get the newly added packages by simply running `cup all`. You can always manually install a new package by using `cinst` or `choco install` command.
* For a list of available packages to use, please refer to [packages.csv](packages.csv)
* Create and configure a new Windows Virtual Machine.
* Take your initial snapshot before installing FLARE VM
* Download and copy [`install.ps1`](install.ps1) on to your new VM
* Download and copy [`profile.json`](profile.json) on to your new VM
* Download and copy [`flarevm.installer.flare`](flarevm.installer.flare) or [`flarevm.win10.installer.fireeye`](flarevm.win10.installer.fireeye) directory on to your new VM
* Modify the `profile.json` file:
  * Most of the fields within `env` data should be left unchanged.
  * Modify the `TEMPLATE_DIR` entry to match the correct template for your VM.
  * Modify the `packages` list in the `JSON` file to only include the packages you would like to install. Please refer to [packages.csv](packages.csv) for a full list of packages available
* Open `PowerShell` as an Administrator
* Enable script execution by running the following command:
  * `Set-ExecutionPolicy unrestricted`
* Finally, execute the installer by providing `profile.json` using the `-profile_file` switch, assuming `profile.json`, `install.ps1` and the template directory (`flarevm.installer.flare` or `flarevm.win10.installer.fireeye`) are all in the same directory:
  * `.\install.ps1 -profile_file profile.json`
  * Optionally, you can also pass the following flags:
    * `-password <current_user_password>`: Use the specified password instead of prompting user

Installing Additional Packages
========================

FLARE VM uses both the Chocolatey public and custom FireEye package repositories making it easy to install additional packages. For example, enter the command below as an Administrator to install `x64dbg` on your system:

    cinst x64dbg


Staying up to Date
==================

Type the following command to update all of the packages to the most recent version:

    cup all

Malware Analysis with FLARE VM
==============================

For an example malware analysis session using FLARE VM, please see the blog at [https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html](https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html).

> The installation instructions referenced in the above blog post are outdated. For installation instructions, follow the steps outlined in the blog [https://www.fireeye.com/blog/threat-research/2018/11/flare-vm-update.html](https://www.fireeye.com/blog/threat-research/2018/11/flare-vm-update.html).

Installed Tools
===============

Android
---------
* dex2jar
* apktool

Debuggers
---------
* flare-qdb
* scdbg
* OllyDbg + OllyDump + OllyDumpEx
* OllyDbg2 + OllyDumpEx
* x64dbg
* WinDbg + OllyDumpex + pykd

Decompilers
---------
* RetDec

Delphi
---------
* Interactive Delphi Reconstructor (IDR)

Developer Tools
---------
* VC Build Tools
* NASM

Disassemblers
---------
* Ghidra
* IDA Free (5.0 & 7.0)
* Binary Ninja Demo
* radare2
* Cutter

.NET
---------
* de4dot
* Dot Net String Decoder (DNSD)
* dnSpy
* DotPeek
* ILSpy
* RunDotNetDll

AutoIt
---------
* AutoItExtractor
* UnAutoIt
* Exe2Aut

Flash
---------
* FFDec

Forensic
---------
* Volatility
* Autopsy

Hex Editors
---------
* FileInsight
* HxD
* 010 Editor

Java
---------
* JD-GUI
* Bytecode-Viewer
* Java-Deobfuscator

JavaScript
---------
* malware-jail

Networking
---------
* FakeNet-NG
* ncat
* nmap
* Wireshark

Office
---------
* Offvis
* OfficeMalScanner
* oledump.py
* rtfdump.py
* msoffcrypto-crack.py

PDF
---------
* PDFiD
* PDFParser
* PDFStreamDumper

PE
---------
* PEiD
* ExplorerSuite (CFF Explorer)
* PEview
* DIE
* PeStudio
* PEBear
* ResourceHacker
* LordPE
* PPEE(puppy)

Pentest
---------
* Windows binaries from Kali Linux

Powershell
---------
* PSDecode

Text Editors
---------
* SublimeText3
* Notepad++
* Vim

Visual Basic
---------
* VBDecompiler

Web Application
---------
* BurpSuite Free Edition
* HTTrack

Utilities
---------
* FLOSS
* HashCalc
* HashMyFiles
* Checksum
* 7-Zip
* Far Manager
* Putty
* Wget
* RawCap
* UPX
* RegShot
* Process Hacker
* Sysinternals Suite
* API Monitor
* SpyStudio
* Shellcode Launcher
* Cygwin
* Unxutils
* Malcode Analyst Pack (MAP)
* XORSearch
* XORStrings
* Yara
* CyberChef
* KernelModeDriverLoader
* Process Dump
* Innounp
* InnoExtract
* UniExtract2
* Hollows-Hunter
* PE-sieve
* ImpRec
* ProcDot

Python, Modules, Tools
---------
* Py2ExeDecompiler
* pyinstxtractor
* Python 2.7
  * hexdump
  * pefile
  * winappdbg
  * pycryptodome
  * vivisect
  * binwalk
  * capstone-windows
  * unicorn
  * oletools
  * olefile
  * unpy2exe
  * uncompyle6
  * pycrypto
  * pyftpdlib
  * pyasn1
  * pyOpenSSL
  * ldapdomaindump
  * pyreadline
  * flask
  * networkx
  * requests
  * msoffcrypto-tool
  * yara-python
  * mkyara
* Python 3.7
  * binwalk
  * unpy2exe
  * uncompyle6
  * StringSifter
  * hexdump
  * pycryptodome
  * oletools
  * olefile
  * msoffcrypto-tool
  * pyftpdlib
  * pyasn1
  * pyOpenSSL
  * acefile
  * requests
  * yara-python
  * mkyara

Other
---------
* VC Redistributable Modules (2005, 2008, 2010, 2012, 2013, 2015, 2017)
* .NET Framework versions 4.8
* Practical Malware Analysis Labs
* Google Chrome
* Cmder


Legal Notice
============
<pre>This download configuration script is provided to assist cyber security analysts
in creating handy and versatile toolboxes for malware analysis environments. It
provides a convenient interface for them to obtain a useful set of analysis
tools directly from their original sources. Installation and use of this script
is subject to the Apache 2.0 License.

You as a user of this script must review, accept and comply with the license
terms of each downloaded/installed package listed below. By proceeding with the
installation, you are accepting the license terms of each package, and
acknowledging that your use of each package will be subject to its respective
license terms.

List of package licenses:

http://exeinfo.atwebpages.com
http://go.microsoft.com/fwlink/?LinkID=251960
http://jd.benow.ca/
http://msdn.microsoft.com/en-US/cc300389.aspx
http://ntinfo.biz
https://www.sublimetext.com
http://opensource.org/licenses/MIT
http://progress-tools.x10.mx/dnsd.html
http://sandsprite.com/CodeStuff/scdbg_manual/MANUAL_EN.html
http://sandsprite.com/iDef/MAP/
http://sandsprite.com/iDef/SysAnalyzer/
http://sandsprite.com/tools.php?id=17
http://svn.code.sf.net/p/processhacker/code/2.x/trunk/LICENSE.txt
http://technet.microsoft.com/en-us/sysinternals/bb469936
http://upx.sourceforge.net/upx-license.html
http://vimdoc.sourceforge.net/htmldoc/uganda.html
http://whiteboard.nektra.com/spystudio/spystudio_license
http://wjradburn.com/software/
http://www.7-zip.org/license.txt
http://www.angusj.com/resourcehacker/
http://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html
http://www.gnu.org/copyleft/gpl.html
http://www.gnu.org/licenses/gpl-2.0.html
http://www.novirusthanks.org/products/kernel-mode-driver-loader/
http://www.ntcore.com/exsuite.php
http://wjradburn.com/software/
http://www.ollydbg.de/download.htm
http://www.ollydbg.de/version2.html
http://www.oracle.com/technetwork/java/javase/terms/license/index.html
http://www.radare.org/r/license.html
http://www.rohitab.com/apimonitor
http://www.slavasoft.com/hashcalc/license-agreement.htm
http://www.techworld.com/download/portable-applications/microsoft-offvis-11-3214034/
https://blog.didierstevens.com/programs/pdf-tools/
https://blog.didierstevens.com/programs/xorsearch/
https://bytecodeviewer.com/
https://cdn.rawgit.com/iggi131/packages/master/RawCap/license.txt
https://docs.binary.ninja/about/license/#demo-license
https://docs.binary.ninja/about/license/index.html#demo-license
https://github.com/0xd4d/de4dot/blob/master/LICENSE.de4dot.txt
https://github.com/0xd4d/dnSpy
https://github.com/0xd4d/dnSpy/blob/master/dnSpy/dnSpy/LicenseInfo/GPLv3.txt
https://github.com/FarGroup/FarManager/blob/master/LICENSE
https://github.com/clinicallyinane/shellcode_launcher/
https://github.com/enkomio/RunDotNetDll/blob/master/LICENSE.TXT
https://github.com/fireeye/flare-fakenet-ng
https://github.com/fireeye/flare-floss
https://github.com/fireeye/flare-qdb
https://github.com/fireeye/flare-vm
https://github.com/icsharpcode/ILSpy/blob/master/README.txt
https://github.com/icsharpcode/ILSpy/blob/master/doc/license.txt
https://github.com/java-decompiler/jd-gui/blob/master/LICENSE
https://github.com/mikesiko/PracticalMalwareAnalysis-Labs
https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/LICENSE
https://github.com/radareorg/cutter
https://github.com/x64dbg/x64dbg/blob/development/LICENSE
https://github.com/x64dbg/x64dbgpy/blob/v25/LICENSE
https://hshrzd.wordpress.com/pe-bear/
https://github.com/hasherezade/hollows_hunter/blob/master/LICENSE
https://github.com/hasherezade/pe-sieve/blob/master/LICENSE
https://metasploit.com/
https://mh-nexus.de/en/hxd/license.php
https://nmap.org/ncat/
https://portswigger.net/burp
https://raw.githubusercontent.com/IntelliTect/Licenses/master/WindowsManagementFramework.txt
https://raw.githubusercontent.com/chocolatey/choco/master/LICENSE
https://raw.githubusercontent.com/ferventcoder/checksum/master/LICENSE
https://retdec.com/
https://svn.nmap.org/nmap/COPYING
https://www.7-zip.org/
https://www.free-decompiler.com/flash/license/
https://www.gnu.org/copyleft/gpl.html
https://www.hex-rays.com/products/ida/support/download_freeware.shtml
https://www.jetbrains.com/decompiler/download/license.html
https://www.kali.org/about-us/
https://www.mcafee.com/hk/downloads/free-tools/fileinsight.aspx
https://www.microsoft.com/en-us/download/details.aspx?id=44266
https://www.nirsoft.net/utils/hash_my_files.html
https://www.openssl.org/source/license.html
https://www.python.org/download/releases/2.7/license
https://docs.python.org/3/license.html
https://www.sweetscape.com/010editor/manual/License.htm
https://www.vb-decompiler.org/license.htm
http://kpnc.org/idr32/en/
https://www.vim.org/about.php
https://www.winitor.com
https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/LICENSE
https://www.mzrst.com/
https://raw.githubusercontent.com/dscharrer/innoextract/master/LICENSE
http://innounp.sourceforge.net/
https://www.visualstudio.com/en-us/support/legal/mt644918
http://repo.or.cz/w/nasm.git/blob_plain/HEAD:/LICENSE
https://blog.didierstevens.com/programs/oledump-py/
https://lessmsi.activescott.com/
https://cert.at/downloads/software/bytehist_en.html
https://github.com/ReFirmLabs/binwalk
https://github.com/fireeye/SilkETW
https://github.com/fireeye/stringsifter
https://github.com/sleuthkit/autopsy
http://www.httrack.com/page/1/en/index.html
https://github.com/java-deobfuscator/deobfuscator
https://github.com/HynekPetrak/malware-jail
https://blog.didierstevens.com/2018/12/31/new-tool-msoffcrypto-crack-py/
https://www.procdot.com
https://github.com/R3MRUM/PSDecode
https://sourceforge.net/projects/pyinstallerextractor/
https://blog.didierstevens.com/2018/12/10/update-rtfdump-py-version-0-0-9/
https://gitlab.com/x0r19x91/autoit-extractor/-/blob/master/LICENSE
https://github.com/fireeye/capa
</pre>
