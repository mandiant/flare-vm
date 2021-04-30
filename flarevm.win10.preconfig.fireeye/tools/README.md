## Contents
 - [Description](#description)
 - [Usage](#usage)
 - [FAQ](#faq)
 - [Windows builds overview](#windows-builds-overview)
 - [Advanced usage](#advanced-usage)
 - [Maintaining own forks](#maintaining-own-forks)
 - [Contribution guidelines](#contribution-guidelines)

&nbsp;

## Description

This is a PowerShell script for automation of routine tasks done after fresh installations of Windows 10 and Windows Server 2016 / 2019. This is by no means any complete set of all existing Windows tweaks and neither is it another "antispying" type of script. It's simply a setting which I like to use and which in my opinion make the system less obtrusive.

&nbsp;

## Usage
If you just want to run the script with the default preset, download and unpack the [latest release](https://github.com/Disassembler0/Win10-Initial-Setup-Script/releases) and then simply double-click on the *Default.cmd* file and confirm *User Account Control* prompt. Make sure your account is a member of *Administrators* group as the script attempts to run with elevated privileges.

The script supports command line options and parameters which can help you customize the tweak selection or even add your own custom tweaks, however these features require some basic knowledge of command line usage and PowerShell scripting. Refer to [Advanced usage](#advanced-usage) section for more details.

&nbsp;

## FAQ

**Q:** Can I run the script safely?  
**A:** Definitely not. You have to understand what the functions do and what will be the implications for you if you run them. Some functions lower security, hide controls or uninstall applications. **If you're not sure what the script does, do not attempt to run it!**

**Q:** Can I run the script repeatedly?  
**A:** Yes! In fact the script has been written to support exactly that, as it's not uncommon that big Windows Updates reset some of the settings.

**Q:** Which versions and editions of Windows are supported?  
**A:** The script aims to be fully compatible with the most up-to-date 64bit version of Windows 10 receiving updates from semi-annual channel, however if you create your own preset and exclude the incompatible tweaks, it will work also on LTSB/LTSC and possibly also on 32bit systems. Vast majority of the tweaks will work on all Windows editions. Some of them rely on group policy settings, so there may be a few limitations for Home and Education editions.

**Q:** Can I run the script on Windows Server 2016 or 2019?  
**A:** Yes. Starting from version 2.5, Windows Server is supported. There are even few tweaks specific to Server environment. Keep in mind though, that the script is still primarily designed for Windows 10, so you have to create your own preset.

**Q:** Can I run the script on Windows 7, 8, 8.1 or other versions of Windows?  
**A:** No. Although some tweaks may work also on older versions of Windows, the script is developed only for Windows 10 and Windows Server 2016 / 2019. There are no plans to support older versions.

**Q:** Can I run the script in multi-user environment?  
**A:** Yes, to certain extent. Some tweaks (most notably UI tweaks) are set only for the user currently executing the script. As stated above, the script can be run repeatedly; therefore it's possible to run it multiple times, each time as different user. Due to the nature of authentication and privilege escalation mechanisms in Windows, most of the tweaks can be successfully applied only by users belonging to *Administrators* group. Standard users will get an UAC prompt asking for admin credentials which then causes the tweaks to be applied to the given admin account instead of the original non-privileged one. There are a few ways how this can be circumvented programmatically, but I'm not planning to include any as it would negatively impact code complexity and readability. If you still wish to try to use the script in multi-user environment, check [this answer in issue #29](https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/29#issuecomment-333040591) for some pointers.

**Q:** Did you test the script?  
**A:** Yes. I'm testing new additions on up-to-date 64bit Home and Enterprise editions in VMs. I'm also regularly using it for all my home installations after all bigger updates.

**Q:** I've run the script and it did something I don't like, how can I undo it?  
**A:** For every tweak, there is also a corresponding function which restores the default settings. The default is considered freshly installed Windows 10 or Windows Server 2016 with no adjustments made during or after the installation. Use the tweaks to create and run new preset. Alternatively, since some functions are just automation for actions which can be done using GUI, find appropriate control and modify it manually.

**Q:** I've run the script and some controls are now greyed out and display message "*Some settings are hidden or managed by your organization*", why?  
**A:** To ensure that system-wide tweaks are applied smoothly and reliably, some of them make use of *Group Policy Objects* (*GPO*). The same mechanism is employed also in companies managing their computers in large scale, so the users without administrative privileges can't change the settings. If you wish to change a setting locked by GPO, apply the appropriate restore tweak and the control will become available again.

**Q:** I've run the script and it broke my computer / killed neighbor's dog / caused world war 3.  
**A:** I don't care. Also, that's not a question.

**Q:** I'm using a tweak for &lt;feature&gt; on my installation, can you add it?  
**A:** Submit a PR, create a feature request issue or drop me a message. If I find the functionality simple, useful and not dependent on any 3rd party modules or executables (including also *Chocolatey*, *NuGet*, *Ninite* or other automation solutions), I might add it.

**Q:** Can I use the script or modify it for my / my company's needs?  
**A:** Sure, knock yourself out. Just don't forget to include copyright notice as per MIT license requirements. I'd also suggest including a link to this GitHub repo as it's very likely that something will be changed, added or improved to keep track with future versions of Windows 10.

**Q:** Why are there repeated pieces of code throughout some functions?  
**A:** So you can directly take a function block or a line from within a function and use it elsewhere, without elaborating on any dependencies.

**Q:** For how long are you going to maintain the script?  
**A:** As long as I use Windows 10.

**Q:** I really like the script. Can I send a donation?  
**A:** Feel free to send donations via [PayPal](https://www.paypal.me/Disassembler). Any amount is appreciated, but keep in mind that donations are completely voluntary and I'm not obliged to make any script adjustments in your favor regardless of the donated amount. You can also drop me a mail to discuss an alternative way.

&nbsp;

## Windows builds overview

| Version |        Code name        |     Marketing name     | Build |
| :-----: | ----------------------- | ---------------------- | :---: |
|  1507   | Threshold 1 (TH1 / RTM) | N/A                    | 10240 |
|  1511   | Threshold 2 (TH2)       | November Update        | 10586 |
|  1607   | Redstone 1 (RS1)        | Anniversary Update     | 14393 |
|  1703   | Redstone 2 (RS2)        | Creators Update        | 15063 |
|  1709   | Redstone 3 (RS3)        | Fall Creators Update   | 16299 |
|  1803   | Redstone 4 (RS4)        | April 2018 Update      | 17134 |
|  1809   | Redstone 5 (RS5)        | October 2018 Update    | 17763 |
|  1903   | 19H1                    | May 2019 Update        | 18362 |
|  1909   | 19H2                    | November 2019 Update   | 18363 |
|  2004   | 20H1                    | TBA                    | 19041 |

&nbsp;

## Advanced usage

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Win10.ps1 [-include filename] [-preset filename] [-log logname] [[!]tweakname]

    -include filename       load module with user-defined tweaks
    -preset filename        load preset with tweak names to apply
    -log logname            save script output to a file
    tweakname               apply tweak with this particular name
    !tweakname              remove tweak with this particular name from selection

### Presets

The tweak library consists of separate idempotent functions, containing one tweak each. The functions can be grouped to *presets*. Preset is simply a list of function names which should be called. Any function which is not present or is commented in a preset will not be called, thus the corresponding tweak will not be applied. In order for the script to do something, you need to supply at least one tweak library via `-include` and at least one tweak name, either via `-preset` or directly as command line argument.

The tweak names can be prefixed with exclamation mark (`!`) which will instead cause the tweak to be removed from selection. This is useful in cases when you want to apply the whole preset, but omit a few specific tweaks in the current run. Alternatively, you can have a preset which "patches" another preset by adding and removing a small amount of tweaks.

To supply a customized preset, you can either pass the function names directly as arguments.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Win10.ps1 -include Win10.psm1 EnableFirewall EnableDefender

Or you can create a file where you write the function names (one function name per line, no commas or quotes, whitespaces allowed, comments starting with `#`) and then pass the filename using `-preset` parameter.  
Example of a preset file `mypreset.txt`:

    # Security tweaks
    EnableFirewall
    EnableDefender

    # UI tweaks
    ShowKnownExtensions
    ShowHiddenFiles   # Only hidden, not system

Command using the preset file above:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Win10.ps1 -include Win10.psm1 -preset mypreset.txt

### Includes

The script also supports inclusion of custom tweaks from user-supplied modules passed via `-include` parameter. The content of the user-supplied module is completely up to the user, however it is strongly recommended to have the tweaks separated in respective functions as the main tweak library has. The user-supplied scripts are loaded into the main script via `Import-Module`, so the library should ideally be a `.psm1` PowerShell module. 
Example of a user-supplied tweak library `mytweaks.psm1`:

```powershell
Function MyTweak1 {
    Write-Output "Running MyTweak1..."
    # Do something
}

Function MyTweak2 {
    Write-Output "Running MyTweak2..."
    # Do something else
}
```

Command using the script above:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Win10.ps1 -include mytweaks.psm1 MyTweak1 MyTweak2

### Combination

All features described above can be combined. You can have a preset which includes both tweaks from the original script and your personal ones. Both `-include` and `-preset` options can be used more than once, so you can split your tweaks into groups and then combine them based on your current needs. The `-include` modules are always imported before the first tweak is applied, so the order of the command line parameters doesn't matter and neither does the order of the tweaks (except for `RequireAdmin`, which should always be called first and `Restart`, which should be always called last). It can happen that some tweaks are applied more than once during a singe run because you have them in multiple presets. That shouldn't cause any problems as the tweaks are idempotent.  
Example of a preset file `otherpreset.txt`:

    MyTweak1
    MyTweak2
    !ShowHiddenFiles   # Will remove the tweak from selection
    WaitForKey

Command using all three examples combined:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Win10.ps1 -include Win10.psm1 -include mytweaks.psm1 -preset mypreset.txt -preset otherpreset.txt Restart

&nbsp;

### Logging

If you'd like to store output from the script execution, you can do so using `-log` parameter followed by a filename of the log file you want to create. For example:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Win10.ps1 -include Win10.psm1 -preset mypreset.txt -log myoutput.log

The logging is done using PowerShell `Start-Transcript` cmdlet, which writes extra information about current environment (date, machine and user name, command used for execution etc.) to the beginning of the file and logs both standard output and standard error streams.

## Maintaining own forks

The easiest way to customize the script settings it is to create your own preset and, if needed, your own tweak scripts as described above. For easy start, you can base the modifications on the *Default.cmd* and *Default.preset* and maintain just that. If you choose to fork the script anyway, you don't need to comment or remove the actual functions in *Win10.psm1*, because if they are not called, they are not used.

If you wish to make more elaborate modifications of the basic script and incorporate some personal tweaks or adjustments, then I suggest doing it in a following way:

1. Fork the repository on GitHub (obviously).
2. Clone your fork on your computer.

    ```
    git clone https://github.com/<yournamehere>/Win10-Initial-Setup-Script
    cd Win10-Initial-Setup-Script
    ```

3. Add the original repository as a remote (*upstream*).

    ```
    git remote add upstream https://github.com/Disassembler0/Win10-Initial-Setup-Script
    ```

4. Commit your modifications as you see fit.
5. Once there are new additions in the upstream, create a temporary branch, fetch the changes and reset the branch to be identical with this repository.

    ```
    git branch upstream
    git checkout upstream
    git fetch upstream
    git reset --hard upstream/master
    ```

6. When you have the upstream branch up to date, check back your master and rebase it based on the upstream branch. If there are some conflicts between the changesets, you'll be asked to resolve them manually.

    ```
    git checkout master
    git rebase upstream
    ```

7. Eventually, delete the upstream branch and force push your changes back onto GitHub.

    ```
    git branch -D upstream
    git push -f master
    ```

**Word of warning:** Rebasing and force-pushing will change the history of your commits. The upside is that your adjustments will always stay on top of the commit history. The downside is that everybody remote-tracking your repository will always have to rebase and force-push too, otherwise their commit history will not match yours.

&nbsp;

## Contribution guidelines

Following is a list of rules which I'm trying to apply in this project. The rules are not binding and I accept pull requests even if they don't adhere to them, as long as their purpose and content are clear. In cases when there are too many rule violations, I might simply redo the whole functionality and reject the PR while still crediting you. If you'd like to make my work easier, please consider adhering to the following rules too.

### Function naming
Try to give a function a meaningful name up to 25 characters long, which gives away the purpose of the function. Use verbs like `Enable`/`Disable`, `Show`/`Hide`, `Install`/`Uninstall`, `Add`/`Remove` in the beginning of the function name. In case the function doesn't fit any of these verbs, come up with another name, beginning with the verb `Set`, which indicates what the function does, e.g. `SetCurrentNetworkPrivate` and `SetCurrentNetworkPublic`.

### Revert functions
Always add a function with opposite name (or equivalent) which reverts the behavior to default. The default is considered freshly installed Windows 10 or Windows Server 2016 / 2019 with no adjustments made during or after the installation. If you don't have access to either of these, create the revert function to the best of your knowledge and I will fill in the rest if necessary.

### Function similarities
Check if there isn't already a function with similar purpose as the one you're trying to add. As long as the name and objective of the existing function is unchanged, feel free to add your tweak to that function rather than creating a new one.

### Function grouping
Try to group functions thematically. There are already several major groups (privacy, security, services etc.), but even within these, some tweaks may be related to each other. In such case, add a new tweak below the existing one and not to the end of the whole group.

### Default preset
Always add a reference to the tweak and its revert function in the *Default.preset*. Add references to both functions on the same line (mind the spaces) and always comment out the revert function. Whether to comment out also the tweak in the default preset is a matter of personal preference. The rule of thumb is that if the tweak makes the system faster, smoother, more secure and less obtrusive, it should be enabled by default. Usability has preference over performance (that's why e.g. indexing is kept enabled).

### Repeatability
Unless applied on unsupported system, all functions have to be applicable repeatedly without any errors. When you're creating a registry key, always check first if the key doesn't happen to already exist. When you're deleting registry value, always append `-ErrorAction SilentlyContinue` to prevent errors while deleting already deleted values.

### Input / output hiding
Suppress all output generated by commands and cmdlets using `| Out-Null` or `-ErrorAction SilentlyContinue` where applicable. Whenever an input is needed, use appropriate arguments to suppress the prompt and programmatically provide values for the command to run (e.g. using `-Confirm:$false`). The only acceptable output is from the `Write-Output` cmdlets in the beginning of each function and from non-suppressible cmdlets like `Remove-AppxPackage`.

### Registry
Create the registry keys only if they don't exist on fresh installation if Windows 10 or Windows Server 2016 / 2019. When deleting registry, delete only registry values, not the whole keys. When you're setting registry values, always use `Set-ItemProperty` instead of `New-ItemProperty`. When you're removing registry values, choose either `Set-ItemProperty` or `Remove-ItemProperty` to reinstate the same situation as it was on the clean installation. Again, if you don't know what the original state was, let me know in PR description and I will fill in the gaps. When you need to use `HKEY_USERS` registry hive, always add following snippet before the registry modification to ensure portability.

```powershell
If (!(Test-Path "HKU:")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
```

### Force usage
Star Wars jokes aside, don't use `-Force` option unless absolutely necessary. The only permitted case is when you're creating a new registry key (not a value) and you need to ensure that all parent keys will be created as well. In such case always check first if the key doesn't already exist, otherwise you will delete all its existing values.

### Comments
Always add a simple comment above the function briefly describing what the function does, especially if it has an ambiguous name or if there is some logic hidden under the hood. If you know that the tweak doesn't work on some editions of Windows 10 or on Windows Server, state it in the comment too. Add a `Write-Output` cmdlet with the short description of action also to the first line of the function body, so the user can see what is being executed and which function is the problematic one whenever an error occurs. The comment is written in present simple tense, the `Write-Output` in present continuous with ellipsis (resp. three dots) at the end.

### Coding style
Indent using tabs, enclose all string values in double quotes (`"`) and strictly use `PascalCase` wherever possible. Put opening curly bracket on the same line as the function name or condition, but leave the closing bracket on a separate line for readability.

### Examples

**Naming example**: Consider function `EnableFastMenu`. What does it do? Which menu? How fast is *fast*? A better name might be `EnableFastMenuFlyout`, so it's a bit clearer that we're talking about the menu flyouts delays. But the counterpart function would be `DisableFastMenuFlyouts` which is not entirely true. We're not *disabling* anything, we're just making it slow again. So even better might be to name them `SetFastMenuFlyouts` and `SetSlowMenuFlyouts`. Or better yet, just add the functionality to already existing `SetVisualFXPerformance`/`SetVisualFXAppearance`. Even though the names are not 100% match, they aim to tweak similar aspects and operate within the same registry keys.

**Coding example:** The following code applies most of the rules mentioned above (naming, output hiding, repeatability, force usage, comments and coding style).

```powershell
# Enable some feature
Function EnableSomeFeature {
    Write-Output "Enabling some feature..."
    If (!(Test-Path "HKLM:\Some\Registry\Key")) {
        New-Item -Path "HKLM:\Some\Registry\Key" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Some\Registry\Key" -Name "SomeValueName" -Type String -Value "SomeValue"
}

# Disable some feature
Function DisableSomeFeature {
    Write-Output "Disabling some feature..."
    Remove-ItemProperty -Path "HKLM:\Some\Registry\Key" -Name "SomeValueName" -ErrorAction SilentlyContinue
}
```
