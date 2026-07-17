# FLARE-VM Code Improvement Report

_Analysis date: 2026-07-17 — scope: `install.ps1`, `virtualbox/*.py`, `virtualbox/install.sh`, CI._

This report is the result of a deep read of the FLARE-VM installer and its VirtualBox
automation tooling. Findings are grouped by severity and each one cites the file and line so
it can be acted on directly. A prioritized action list is at the end.

---

## 1. Confirmed bugs

### 1.1 `--dynamic_only` scans the wrong set of VMs (High)
**File:** `virtualbox/vbox-adapter-check.py:78`

```python
if not (dynamic_only and (DYNAMIC_VM_NAME in vm_name)):
    vms_list.append((vm_name, vm_uuid))
```

The condition is inverted. Truth table with `dynamic_only=True`:

| VM name contains `.dynamic` | Appended? | Expected |
|---|---|---|
| yes | **no** | yes |
| no  | **yes** | no |

So `--dynamic_only` returns exactly the VMs it should exclude, and **skips the `.dynamic`
malware-analysis VMs whose internet you most want to disable**. This defeats the purpose of the
flag for the security use case. It should be:

```python
if (not dynamic_only) or (DYNAMIC_VM_NAME in vm_name):
    vms_list.append((vm_name, vm_uuid))
```

### 1.2 `$filter` OData query is silently dropped (High)
**File:** `install.ps1:1182`

```powershell
$vmPackagesUrl = "https://www.myget.org/F/vm-packages/api/v2/Packages?$filter=IsLatestVersion%20eq%20true"
```

Inside a double-quoted PowerShell string, `$filter` is interpreted as a (never-defined)
variable and expands to empty. The URL sent is `...Packages?=IsLatestVersion%20eq%20true`,
so the server-side "latest version only" filter is not applied. The code compensates by
re-checking `IsLatestVersion -eq "true"` per entry (line 1205), but it means every package
version is downloaded and paged through, making package discovery much slower than intended.
Fix by escaping the `$` or single-quoting:

```powershell
$vmPackagesUrl = 'https://www.myget.org/F/vm-packages/api/v2/Packages?$filter=IsLatestVersion eq true'
```

### 1.3 Malformed snapshot rename produces a broken name (Medium)
**File:** `virtualbox/vboxcommon.py:358`

```python
run_vboxmanage(["snapshot", vm_uuid, "edit", snapshot_name, f"--name='{snapshot_name} OLD"])
```

Quotes are mismatched (opening `'`, no closing quote, stray trailing `"` from the f-string).
The resulting snapshot name literally becomes `'<name> OLD` with a leading single quote, and
because the loop renames "as many times as there are duplicates" but each pass searches for the
original `snapshot_name`, subsequent iterations no longer match the just-renamed snapshot. The
intended value is simply:

```python
f"--name={snapshot_name} OLD"
```

### 1.4 Undefined `$configPathUrl` in user-facing message (Low)
**File:** `install.ps1:1143`

```powershell
Write-Host "`t[-] Please download config.xml from $configPathUrl to your desktop" ...
```

`$configPathUrl` is never assigned, so the instruction prints with a blank URL. Use the actual
source variable (`$configSource`) or the hardcoded raw GitHub URL.

---

## 2. Robustness & reliability

### 2.1 Internet check hard-fails on blocked ICMP
**File:** `install.ps1:153` (`Test-WebConnection`)

The check does `Test-Connection $url -Quiet` (ICMP ping) first and returns an error if ping
fails, before ever trying HTTPS. Many corporate/host networks block ICMP while allowing HTTPS,
so a working environment can be reported as "no internet." Prefer making the HTTPS `Invoke-WebRequest`
authoritative and treating ping as advisory only.

### 2.2 `wait_until` docstring vs. behavior mismatch
**File:** `virtualbox/vboxcommon.py:280-294`

Docstring says "within one minute"; the actual `timeout` is 600 seconds. Also, `condition` is
passed as a string and run through `eval()` (see 3.4). Update the docstring to 10 minutes.

### 2.3 `VERR_NO_LOW_MEMORY` retry loop can run forever
**File:** `virtualbox/vboxcommon.py:84-91`

The `while ... VERR_NO_LOW_MEMORY` loop retries every 60s with no maximum attempts. If the host
never frees low memory, the script hangs indefinitely with no operator escape. Add a bounded
retry count / total-timeout and then raise.

### 2.4 `VMname` env var set inside a loop
**File:** `install.ps1:1755-1760`

```powershell
foreach ($env in $configXml.config.envs.env) {
    ...
    [Environment]::SetEnvironmentVariable('VMname', 'FLARE-VM', [EnvironmentVariableTarget]::Machine)
}
```

The constant `VMname` is re-set on every iteration of the env loop. Harmless but wasteful; move
it outside the loop.

### 2.5 Boxstarter version parse is fragile
**File:** `install.ps1:1067-1068`

`choco info -l -r "boxstarter" | ForEach-Object { $name, $version = $_ -split '\|' }` leaves
`$version` as whatever the last output line yielded; if `choco info` emits extra lines the parse
can pick up the wrong token, and `[System.Version]$version` then throws under
`$ErrorActionPreference='Stop'`. Constrain the parse to the matching package line.

---

## 3. Code quality & maintainability

### 3.1 `install.ps1` is a 1,844-line monolith
Pre-install checks, three separate WinForms GUIs, package discovery, and the Boxstarter install
flow all live in one file. The GUI control definitions alone (lines ~436-1050 and ~1446-1733) are
hundreds of lines of repetitive `New-Object ... Label/Font/Location` boilerplate. Extract into
modules (e.g., `checks.ps1`, `gui.ps1`, `packages.ps1`) or a helper that builds a control from a
small spec hashtable. This would cut the file substantially and make the GUI layout maintainable.

### 3.2 Duplicated function definition
**File:** `install.ps1:1243` and `install.ps1:1353`

`Get-AdditionalPackages` is defined twice with identical bodies (one at top level, one nested in
the GUI block). Keep a single definition.

### 3.3 Dead / unused variable
**File:** `install.ps1:1573` — `$numCategories++` is incremented but the variable is never
initialized or read. Remove it.

### 3.4 `eval()` on a passed-in string
**File:** `virtualbox/vboxcommon.py:290`

`wait_until` takes `condition` as a string and calls `eval(condition)`. All current call sites
pass trusted literals, but this is a fragile pattern. Pass a callable (lambda) instead:

```python
def wait_until(vm_uuid, predicate):  # predicate: Callable[[], bool]
    ...
    if predicate():
        ...
```

### 3.5 Inconsistent indentation in the check functions
**File:** `install.ps1:172-217` — `Test-PSVersion`, `Test-Admin`, etc. mix tabs and spaces,
which shows up as ragged nesting. Run the repo's own linter (`scripts/lint.ps1`) and PSScriptAnalyzer
formatting to normalize.

### 3.6 `control_guest` swallows the first error and blindly waits 2 minutes
**File:** `virtualbox/vboxcommon.py:116-122`

On any `RuntimeError` it sleeps 120s and retries once, regardless of whether the failure was the
"guest additions not ready yet" case or a genuine error (bad credentials, VM gone). Narrow the
retry to the transient condition where possible, and surface the original error on the second failure.

---

## 4. Security considerations

These are inherent to what FLARE-VM does (it is a malware-analysis lab installer that
intentionally disables Defender and runs remote code). They are noted for awareness, not as
defects to "fix," but a couple are worth hardening.

- **Remote script executed unpinned** — `install.ps1:1075` runs
  `Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1'))`.
  This is upstream Boxstarter's documented bootstrap, but there is no hash/signature check. A
  compromised or MITM'd endpoint yields SYSTEM-level code execution. Consider pinning to a known
  Boxstarter package/version where feasible.
- **Config/layout downloaded over the network and trusted** — `Get-ConfigFile` (line 119) fetches
  `config.xml` / `LayoutModification.xml` from raw GitHub and parses/executes the resulting package
  set. Expected for this project; document that users supplying `-customConfig` from untrusted
  sources are running arbitrary package installs.
- **Plaintext password handling** — `-password` is accepted as a plain `[string]` (line 86) and
  converted to a `SecureString` later (line 1059). The plaintext lingers in process memory and
  shell history. This is a known Boxstarter-reboot-resiliency tradeoff; worth a doc note steering
  users to the interactive `Get-Credential` path (the default) rather than `-password` on the CLI.

---

## 5. Testing & CI gaps

- **No unit tests for the Python tooling.** The snapshot/adapter logic in `vboxcommon.py`,
  `vbox-adapter-check.py`, and `vbox-clean-snapshots.py` is pure string/regex parsing of
  `VBoxManage` output — highly testable with captured fixture strings, and exactly the kind of code
  where bugs like 1.1 and 1.3 hide. Add `pytest` tests that feed sample `--machinereadable` output
  to the parsers.
- **Linters only.** `.github/workflows/linter.yml` and `scripts/lint.ps1` cover style; there is no
  job that at least import-checks / smoke-runs the Python scripts (e.g. `python -m py_compile` and a
  `--help` invocation) so broken refactors are caught.
- **`install.ps1` has no automated validation** beyond the build-vbox workflow. A PSScriptAnalyzer
  gate in CI would catch undefined variables like `$configPathUrl` (1.4) and `$filter` (1.2)
  automatically.

---

## 6. Documentation

- The `.SYNOPSIS` block has typos: "envrionment" (line 25) and "arugment" (line 26).
- `Test-DefenderAndTamperProtection` (line 202) checks the `WinDefend` service is *not running* and
  Tamper Protection ≠ 5, but the GUI label just says "Windows Defender Disabled" — document what the
  three-way (service + tamper) check actually requires so users know why it fails.
- `virtualbox/install.sh` requires a manual PATH step (lines 70-80); consider noting this in
  `virtualbox/README.md` so it isn't missed.

---

## 7. Prioritized action list

Status as of 2026-07-17: items 1-9 are **fixed and verified** (PowerShell parses cleanly,
all Python byte-compiles, 16 unit tests pass, black/flake8/isort clean). Item 10 is
**deferred** — see note below.

| # | Item | Severity | Status | Location |
|---|------|----------|--------|----------|
| 1 | Fix inverted `--dynamic_only` filter | High | ✅ Fixed | `vbox-adapter-check.py:78` |
| 2 | Fix `$filter` string expansion in packages URL | High | ✅ Fixed | `install.ps1` |
| 3 | Fix malformed snapshot rename quotes | Medium | ✅ Fixed | `vboxcommon.py` |
| 4 | Make HTTPS authoritative in `Test-WebConnection` | Medium | ✅ Fixed | `install.ps1` |
| 5 | Bound the `VERR_NO_LOW_MEMORY` retry loop | Medium | ✅ Fixed | `vboxcommon.py` |
| 6 | Add pytest fixtures for VBoxManage parsers | Medium | ✅ Added | `virtualbox/test_vbox_tools.py` |
| 7 | Fix `$configPathUrl`; remove dead `$numCategories`; de-dupe `Get-AdditionalPackages` | Low | ✅ Fixed | `install.ps1` |
| 8 | Replace `eval()` in `wait_until` with a callable | Low | ✅ Fixed | `vboxcommon.py` |
| 9 | Add PSScriptAnalyzer + Python smoke check to CI | Low | ✅ Done | `.github/workflows/test.yml` |
| 10 | Refactor `install.ps1` GUI boilerplate into helpers/modules | Low | ⏸ Deferred | `install.ps1` |

Also fixed along the way: `wait_until` docstring (said "one minute", is 10), the fragile
Boxstarter version parse (`install.ps1`), and the "envrionment"/"arugment" synopsis typos.

**Why #10 is deferred:** restructuring the 1,844-line installer's three WinForms GUIs into
modules is a large change whose only real test is running the interactive installer against
Boxstarter/Chocolatey on Windows — which cannot be exercised in this environment. Doing it
blind would risk silently breaking the installer for no correctness gain. It should be done
on a Windows VM with the ability to actually launch the GUI, as a dedicated change.

**Intentionally left as-is:** `control_guest`'s broad retry-on-any-`RuntimeError` (§3.6).
Narrowing it to only the transient "guest additions not ready" case requires matching
VBoxManage error strings, which could introduce regressions; the current behavior is safe
(it re-raises the real error on the second attempt).
