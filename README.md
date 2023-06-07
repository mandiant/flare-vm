```
                                                              .;,                  
                                                            .;oo'                  
                                                          .,ldo,                   
                                                         ,lddo;                    
                                                       'cdddo;                     
                                                     .codddd:.                     
                                                   .:odddodc.                      
                                                 .;oddddddl.                       
                                               .,ldddddddl'                        
                                             .,lddddddddo,                         
                     .;cccccccc;.          .'cdoddddddddolccccccc:.                
                      ,odddddodd:.       .coododddddddddddddddddo;                 
                       ,odddddddd:.    .:odddddddddddddddddddddd:.                 
                        ;odddddddo;  .;oddddddddddddddddddddddd:.                  
                         ;odddddddo; .,::::::::::::codddddddddc.                   
                         .:ddddddddo,              'lddddddddc.                    
                         .cdddddddddo'            .lddddddddl.                     
                        .ckxdddddddddl.          .cdddddddddl.                     
                       .:xkkxdddddddodl.        .:dddddddddxkl.                    
                       :xkkkkxdddddddddc.      .:dddddddddxxkkl.                   
                      ;xkkkkkxxdddddddddc.     ;dddddddddxkkkkkc.                  
                     ;xkkkkkkkxllddddddddc.   ;oddddddddxxkkkkxxc.                 
                    ,dkkkkkkkxc..ldddddddd:..,odddddddoldkkkkkkkx:.                
                   ,dkxkkkkkkl.  'ldddddddoolodddddddo,.;xkkkkkkkx:                
                  'dkkkkxkkkl.    'ododdddddddddddddo;   :xkkkkkxkx;               
                 'dkkkkkkkko.      ,odddddddddddoddo;     :xkkkkkkkx;              
                .okkkkkkxkd'        ,oddddddddddodd:.     .ckkkkkkkkx,             
               .okkkkkkkkd,          ;oddddddddddd:.       .lkkkxkkxkd,            
              .lkkkxkkkkx;            ;oddddddddd:.         .lkkxkkkkkd'           
             .lkkkkkkkkx;              ;odddddddc.           .okkkkkkkkd'          
            .lkkkkkkkkx:               .:odddodc.             .okkkkkkxko.         
           .ckkkkkkkkkc.                .:ddddc.               'dkxxxxxxko.        
           .;c::cc:c:,.                  .:llc.                 'loooooooo;        
           ________________________________________________________________        
                                       Developed by                                
                                   flarevm@mandiant.com                            
                                  FLARE Team at Mandiant                           
           ________________________________________________________________        
```

# FLARE VM
Welcome to FLARE VM - a collection of software installations scripts for Windows systems that allows you to easily setup and maintain a reverse engineering environment on a virtual machine (VM). FLARE VM was designed to solve the problem of reverse engineering tool curation and relies on two main technologies: [Chocolatey](https://chocolatey.org) and [Boxstarter](https://boxstarter.org). Chocolatey is a Windows-based Nuget package management system, where a "package" is essentially a ZIP file containing PowerShell installation scripts that download and configure a specific tool. Boxstarter leverages Chocolatey packages to automate the installation of software and create repeatable, scripted Windows environments.

## Updates

Our latest updates make FLARE VM more open and maintainable to allow the community to easily add and update tools and make them quickly available to everyone. We've worked hard to open source the packages (see the [VM-packages](https://github.com/mandiant/VM-Packages) repo) which detail how to install and configure analysis tools. The FLARE VM project now uses automatic testing, updating, and releasing to make updated packages immediately installable. See this [blog](https://www.mandiant.com/resources/blog/flarevm-open-to-public) for more information regarding recent changes!

### Good to Know Now

* Windows 7 is no longer supported
* Please do a fresh install instead of trying to update an older FLARE VM
* The installer has a GUI and can also run in CLI-only mode
* Contributing is encouraged!!

## Installation

> **Note:** FLARE VM should ONLY be installed on a virtual machine!

* Prepare a Windows 10+ virtual machine
  * Install Windows in the virtual machine, for example using the raw Windows 10 ISO from https://www.microsoft.com/en-us/software-download/windows10ISO (
    * See other options in https://github.com/mandiant/flare-vm/issues/434
  * We recommend:
    * Avoiding usernames containing a space or other special characters
    * Using a disk capacity of at least 80 GB and memory of at least 2 GB
  * Disable Windows Updates (at least until installation is finished)
    * https://www.windowscentral.com/how-stop-updates-installing-automatically-windows-10
  * Disable Tamper Protection and any Anti-Malware solution (e.g., Windows Defender), preferably via Group Policy.
    * Disabling Tamper Protection
      * https://support.microsoft.com/en-us/windows/prevent-changes-to-security-settings-with-tamper-protection-31d51aaa-645d-408e-6ce7-8d7f8e593f87
      * https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-windows-defender-antivirus.html
    * Disabling Windows Defender
      * https://stackoverflow.com/questions/62174426/how-to-permanently-disable-windows-defender-real-time-protection-with-gpo
      * https://www.windowscentral.com/how-permanently-disable-windows-defender-windows-10
      * https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1
* Take a VM snapshot so you can always revert to a state before FLARE VM installation
* Open a `PowerShell` prompt as administrator
* Download the installation script [`installer.ps1`](https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1) to your desktop
  * `(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',"$([Environment]::GetFolderPath("Desktop"))\install.ps1")`
* Unblock the installation script by running:
  * `Unblock-File .\install.ps1`
* Enable script execution by running:
  * `Set-ExecutionPolicy Unrestricted`
    * If you receive an error saying the execution policy is overridden by a policy defined at a more specific scope, you may need to pass a scope in via `Set-ExecutionPolicy Unrestricted -Scope CurrentUser` to view execution policies for all scopes, type `Get-ExecutionPolicy -List`
* Finally, execute the installer script as follow:
  * `.\install.ps1`
    * To pass your password as an argument: `.\install.ps1 -password <password>`
    * To use the CLI-only mode with minimal user interaction: `.\install.ps1 -password <password> -noWait -noGui -noChecks`
    * To use the CLI-only mode with minimal user interaction and a custom config file: `.\install.ps1 -customConfig <config.xml> -password <password> -noWait -noGui -noChecks`
* After installation it is recommended to switch to "host-only" networking mode and take a VM snapshot

### Installer GUI

The installer now features a GUI to enable easy customizations! You may customize:
* Package selection
* Environment variable paths

![Installer GUI](https://github.com/mandiant/flare-vm/blob/main/installer_gui.png)

### Installer CLI

To run the installer in **CLI-only mode** with minimal user interaction, use the following combination of parameters:

```
.\install.ps1 -password <password> -noWait -noGui -noChecks
```

Get full usage information by running `Get-Help .\install.ps1 -Detailed`. Below are the CLI parameter descriptions.

```
PARAMETERS
    -password <String>
        Current user password to allow reboot resiliency via Boxstarter. The script prompts for the password if not provided.

    -noPassword [<SwitchParameter>]
        Switch parameter indicating a password is not needed for reboots.

    -customConfig <String>
        Path to a configuration XML file. May be a file path or URL.

    -noWait [<SwitchParameter>]
        Switch parameter to skip installation message before installation begins.

    -noGui [<SwitchParameter>]
        Switch parameter to skip customization GUI.

    -noReboots [<SwitchParameter>]
        Switch parameter to prevent reboots.

    -noChecks [<SwitchParameter>]
        Switch parameter to skip validation checks (not recommended).
```

### Default FLARE VM Tools

The installer will download [config.xml](https://raw.githubusercontent.com/mandiant/flare-vm/main/config.xml) from the FLARE VM repository. This file contains the default list of packages FLARE VM will install. You may use your own list of default packages by specifying the CLI-argument `-customConfig` and providing either a local file path or URL to your `config.xml` file. For example:

```
.\install.ps1 -customConfig "https://raw.githubusercontent.com/mandiant/flare-vm/main/config.xml"
```

## Post Installation
Previous versions of FLARE VM attempted to configure Windows settings post-installation with the goal of streamlining the system for malware analysis (e.g., disabling noisy services). This version of FLARE VM does not currently attempt to further configure Windows (e.g., removing bloatware). It is up to the user to manually configure their environment further.

Below are links for post-installation tweaks for Windows 10+.
* https://github.com/Sycnex/Windows10Debloater
* https://github.com/Disassembler0/Win10-Initial-Setup-Script

We do encourage you to download and set your background to the FLARE VM logo!
<p align="center">
  <img width="300" height="300" src="flarevm.png?raw=true" alt="FLARE VM"/>
</p>

## Contributing
Want to get started contributing? See the links below to learn how.

### Installer
* [FLARE VM installation script, GUI, and configuration](https://github.com/mandiant/flare-vm)

### Tool Packages
* [Repository of all tool packages (VM-packages)](https://github.com/mandiant/VM-Packages)
* [Documentation and contribution guides for tool packages](https://github.com/mandiant/VM-Packages/wiki)
* [Submit new tool packages or report package related issues](https://github.com/mandiant/VM-Packages/issues)

## Troubleshooting
If your installation fails, please attempt to identify the reason for the installation error by reading through the log files listed below on your system:
* `%VM_COMMON_DIR%\log.txt`
* `%PROGRAMDATA%\chocolatey\logs\chocolatey.log`
* `%LOCALAPPDATA%\Boxstarter\boxstarter.log`

### Installer Error
If the installation failed due to an issue in the installation script (e.g., `install.ps1`), file an issue here: https://github.com/mandiant/flare-vm/issues

> **Note:** Rarely should `install.ps1` be the reason for an installation failure. Most likely it is a specific package or set of packages that are failing (see below).

### Package Error
Packages fail to install from time to time -- this is normal. The most common reasons are outlined below:

1. Failure or timeout from Chocolatey or MyGet to download a `.nupkg` file
2. Failure or timeout due to remote host when downloading a tool
3. Intrusion Detection System (IDS) or AV product (e.g., Windows Defender) prevents a tool download or removes the tool from the system
4. Host specific requirement issue
    1. Untested host
    2. Not enough disk space to install tools
5. Tool fails to build due to dependencies
6. Old tool URL (e.g., `HTTP STATUS 404`)
7. Tool's SHA256 hash has changed from what is hardcoded in the package installation script

Reasons **1-4** are difficult for us to fix since we do not control them. If an issue related to reasons **1-4** is filed, it is unlikely we will be able to assist.

We can help with reasons **5-7** and welcome the community to contribute fixes as well! Please file GitHub issues related to package failures at: https://github.com/mandiant/VM-Packages/issues

## Legal Notice
> This download configuration script is provided to assist cyber security analysts in creating handy and versatile toolboxes for malware analysis environments. It provides a convenient interface for them to obtain a useful set of analysis tools directly from their original sources. Installation and use of this script is subject to the Apache 2.0 License. You as a user of this script must review, accept and comply with the license terms of each downloaded/installed package. By proceeding with the installation, you are accepting the license terms of each package, and acknowledging that your use of each package will be subject to its respective license terms.

