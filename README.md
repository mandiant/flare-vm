      ______ _               _____  ______   __      ____  __ 
     |  ____| |        /\   |  __ \|  ____|  \ \    / /  \/  |
     | |__  | |       /  \  | |__) | |__ _____\ \  / /| \  / |
     |  __| | |      / /\ \ |  _  /|  __|______\ \/ / | |\/| |
     | |    | |____ / ____ \| | \ \| |____      \  /  | |  | |
     |_|    |______/_/    \_\_|  \_\______|      \/   |_|  |_|
                        
      ________________________________________________________
                             Developed by                     
                          Peter Kacherginsky                  
           FLARE (FireEye Labs Advanced Reverse Engineering)  
      ________________________________________________________ 
                                                          

Welcome to FLARE VM - a fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing, etc.

Please see https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html for a blog on installing and using the FLARE VM.

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
https://raw.githubusercontent.com/chocolatey/choco/master/LICENSE
</pre>


Installation
============

Create and configure a new Windows 7 or newer Virtual Machine. To install FLARE VM on an existing Windows VM, you need to run an installation script. The installation script is a Boxstarter script which is used to deploy FLARE VM configurations and a collection of chocolatey packages. The easiest way to run the script is to use Boxstarter's web installer as follows:

1) On the newly created VM, open the following URL in **Internet Explorer** (other browsers are not going to work):

       http://boxstarter.org/package/url?[FLAREVM_SCRIPT]

   Where `FLAREVM_SCRIPT` is a path or URL to the respective FLARE VM script. For example to install the malware analysis edition:

       http://boxstarter.org/package/url?https://raw.githubusercontent.com/fireeye/flare-vm/master/flarevm_malware.ps1

   or if you have downloaded and copied the installation script to the local C drive:

       http://boxstarter.org/package/url?C:\flarevm_malware.ps1

2) Copy `install.bat` and `flarevm_malware.ps1` on the newly created VM and execute `install.bat`.



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

Disassemblers ====

* IDA Free
* Binary Ninja Demo

Java ====
* JD-GUI

Visual Basic ====
* VBDecompiler

Flash ====
* FFDec

.NET ====
* ILSpy
* DNSpy
* DotPeek
* De4dot

Office ====
* Offvis

Hex Editors ====
* FileInsight
* HxD
* 010 Editor

PE ====
* PEiD
* ExplorerSuite (CFF Explorer)
* PEview
* DIE

Text Editors ====
* SublimeText3
* Notepad++
* Vim

Utilities ====
* MD5
* 7zip
* Putty
* Wireshark
* RawCap
* Wget
* UPX
* Sysinternals Suite
* API Monitor
* SpyStudio
* Checksum
* Unxutils

Python, Modules, Tools ====
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

Other ====
* VC Redistributable Modules (2008, 2010, 2012, 2013)
