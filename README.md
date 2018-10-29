      ______ _               _____  ______   __      ____  __
     |  ____| |        /\   |  __ \|  ____|  \ \    / /  \/  |
     | |__  | |       /  \  | |__) | |__ _____\ \  / /| \  / |
     |  __| | |      / /\ \ |  _  /|  __|______\ \/ / | |\/| |
     | |    | |____ / ____ \| | \ \| |____      \  /  | |  | |
     |_|    |______/_/    \_\_|  \_\______|      \/   |_|  |_|

      ________________________________________________________
                             Developed by
           FLARE (FireEye Labs Advanced Reverse Engineering)
                         flarevm@fireeye.com
      ________________________________________________________


Welcome to FLARE VM - a fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing, etc.

Please see https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html for a blog on installing and using the FLARE VM.



Installation (Install Script)
=============================

Create and configure a new Windows 7 or newer Virtual Machine. To install FLARE VM on an existing Windows VM, download and copy `install.ps1` on your analysis machine. On the analysis machine open PowerShell as an Administrator and enable script execution by running the following command:

```
Set-ExecutionPolicy Unrestricted
```

Finally, execute the installer script as follows:

```
.\install.ps1
```

The script will set up the Boxstarter environment and proceed to download and install the FLARE VM environment. You will be prompted for the Administrator password in order to automate host restarts during installation.

Installation (Manually)
=======================

First, install boxstarter. All commands are expected to be executed with Administrator privileges.

If you are using PowerShell V2:

```
Set-ExecutionPolicy Unrestricted
iex ((New-Object System.Net.WebClient).DownloadString('http://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
```

And PowerShell V3 or newest:

```
Set-ExecutionPolicy Unrestricted
. { iwr -useb http://boxstarter.org/bootstrapper.ps1 } | iex; get-boxstarter -Force
```

Next, you can deploy FLARE VM environment by executing the install.ps1 script using Power Shell.

```
.\install.ps1
```



Installing a new package
========================

FLARE VM uses the chocolatey public and custom FLARE package repositories. It is easy to install a new package. For example, enter the following command as Administrator to deploy x64dbg on your system:

    cinst x64dbg


Staying up to date
==================

Type the following command to update all of the packages to the most recent version:

    cup all

Malware Analysis with FLARE VM
==============================

Please see a blog at https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html for an example malware analysis session using FLARE VM.

Installed Tools
===============

Debuggers
---------
* OllyDbg + OllyDump + OllyDumpEx
* OllyDbg2 + OllyDumpEx
* x64dbg
* WinDbg

Disassemblers
---------
* IDA Free
* IDA Free 7.0 (x64 bit only)
* Binary Ninja Demo
* Radare2 framework
* Cutter -- GUI frontend for Radare2

Java
---------
* JD-GUI
* dex2jar

Visual Basic
---------
* VBDecompiler

Flash
---------
* FFDec

.NET
---------
* ILSpy
* DNSpy
* DotPeek
* De4dot

Office
---------
* Offvis

PDF
---------
* pdfid
* pdf-parser
* PdfStreamDumper

Hex Editors
---------
* FileInsight
* HxD
* 010 Editor

PE
---------
* PEiD
* ExplorerSuite (CFF Explorer)
* PEview
* DIE
* PeStudio
* LordPE
* Resource Hacker

Text Editors
---------
* SublimeText3
* Vim
* Notepad++

Utilities
---------
* MD5
* 7zip
* Putty
* Wireshark
* RawCap
* Wget
* UPX
* SysAnalyzer
* Process Hacker
* Sysinternals Suite
* Kernel-Mode driver loader
* API Monitor
* SpyStudio
* Checksum
* Unxutils
* YARA
* Cyber Chef
* `shellcode_launcher`
* Py2ExeDecompiler

Python, Modules, Tools
---------
* Python 2.7
* Hexdump
* PEFile
* Winappdbg
* FakeNet-NG
* Vivisect
* FLOSS
* FLARE_QDB
* PyCrypto
* Cryptography

Other
---------
* VC Redistributable Modules (2008, 2010, 2012, 2013, 2015, 2017)
* Practical Malware Analysis Labs
* MAP -- Malcode  Analyst Pack


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

http://www.ollydbg.de/download.htm, http://www.ollydbg.de/download.htm,
https://github.com/x64dbg/x64dbg/blob/development/LICENSE,
http://go.microsoft.com/fwlink/?LinkID=251960,
https://www.hex-rays.com/products/ida/support/download_freeware.shtml,
https://docs.binary.ninja/about/license/#demo-license,
https://github.com/icsharpcode/ILSpy/blob/master/doc/license.txt,
https://github.com/0xd4d/dnSpy/blob/master/dnSpy/dnSpy/LicenseInfo/GPLv3.txt,
https://www.jetbrains.com/decompiler/download/license.html,
https://github.com/0xd4d/de4dot/blob/master/LICENSE.de4dot.txt,
http://www.oracle.com/technetwork/java/javase/terms/license/index.html,
https://github.com/java-decompiler/jd-gui/blob/master/LICENSE,
https://www.vb-decompiler.org/license.htm, http://kpnc.org/idr32/en/,
https://www.free-decompiler.com/flash/license/,
https://www.mcafee.com/hk/downloads/free-tools/fileinsight.aspx,
https://mh-nexus.de/en/hxd/license.php,
https://www.sweetscape.com/010editor/manual/License.htm,
http://www.ntcore.com/exsuite.php, http://wjradburn.com/software/,
http://ntinfo.biz, https://www.sublimetext.com,
https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/LICENSE,
http://vimdoc.sourceforge.net/htmldoc/uganda.html,
http://www.gnu.org/licenses/gpl-2.0.html,
https://raw.githubusercontent.com/ferventcoder/checksum/master/LICENSE,
http://www.7-zip.org/license.txt,
http://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html,
http://www.gnu.org/copyleft/gpl.html,
https://cdn.rawgit.com/iggi131/packages/master/RawCap/license.txt,
https://www.gnu.org/copyleft/gpl.html,
http://upx.sourceforge.net/upx-license.html,
http://technet.microsoft.com/en-us/sysinternals/bb469936,
http://www.rohitab.com/apimonitor,
http://whiteboard.nektra.com/spystudio/spystudio_license,
http://www.slavasoft.com/hashcalc/license-agreement.htm,
http://www.gnu.org/licenses/gpl-2.0.html,
http://www.techworld.com/download/portable-applications/microsoft-offvis-11-3214034/,
http://exeinfo.atwebpages.com,
https://www.python.org/download/releases/2.7/license/,
https://www.microsoft.com/en-us/download/details.aspx?id=44266,
https://raw.githubusercontent.com/IntelliTect/Licenses/master/WindowsManagementFramework.txt,
http://msdn.microsoft.com/en-US/cc300389.aspx,
https://raw.githubusercontent.com/chocolatey/choco/master/LICENSE,
http://svn.code.sf.net/p/processhacker/code/2.x/trunk/LICENSE.txt
https://github.com/mikesiko/PracticalMalwareAnalysis-Labs
https://blog.didierstevens.com/programs/pdf-tools
http://sandsprite.com/tools.php?id=17
http://www.angusj.com/resourcehacker/
http://www.radare.org/r/
https://hshrzd.wordpress.com/pe-bear/
</pre>
