# ThreatPulse: Lab Setup Guide

How to set up a developer workstation for ThreatPulse. Follow it in order. It was tested on Windows 11 Home with WSL2 Ubuntu 26.04 and VMware Workstation Pro.

**Which parts you need:**
- **Track A (Sense & Enforce):** all of it. Track A hosts the project's single lab VM.
- **Tracks B and C:** Part 2 (WSL) and Part 3 (Claude Code) only. No VM is needed: VM-only checks are run by Track A. See [PLANNING.md](../PLANNING.md) Section 3.

**Golden rule:** your real Windows only gets VS Code and VMware. Code is written in WSL. Anything that changes Windows or simulates an attack runs **only in the VM**.

**Write these down somewhere safe as you go:** the VM encryption password, the VM `lab` account password and security answers, and your Ubuntu password.

---

## Part 1: The lab VM

### 1.1 Install VMware Workstation Pro

1. Create a free Broadcom account at the Broadcom support portal. Then go to **My Downloads → VMware Workstation Pro** and download the latest Windows version. Menu names change often; search the portal for "Workstation Pro" if needed.
2. During installation:
   - **"Install Windows Hypervisor Platform (WHP) automatically": check it.** WSL2 uses Hyper-V, and WHP lets VMware run alongside it. Never remove Hyper-V instead, because that breaks WSL. WHP can be turned off later in *Turn Windows features on or off*.
   - **Install location:** keep the default on C:.
   - **"Add VMware Workstation console tools into system PATH": uncheck.** Otherwise WSL (and Claude Code) could control your VMs.
   - **Enhanced Keyboard Driver: leave unchecked.**
   - Updates/Customer Experience Program: uncheck if you like.
3. **Restart Windows** after installing. If powering on a VM later gives *"Transport (VMDB) error -14: Pipe connection has been broken"*, it's almost always because this restart was skipped. Otherwise check that the **VMware Authorization Service** is running (`services.msc`).
4. On first launch, choose the free/personal-use option.

### 1.2 Get Windows for the VM

Download the **Windows 11 Enterprise Evaluation** ISO (64-bit, English) from the **Microsoft Evaluation Center** (microsoft.com/evalcenter). It's free and valid for **90 days**. Save it on a drive with plenty of space, e.g. `E:\threatpulse-vm\iso\`.

### 1.3 Create the VM

**File → New Virtual Machine → Typical**:
- Installer disc image (ISO): the downloaded ISO
- Guest OS: Windows 11 x64
- Name `ThreatPulse-Lab`, location on the large drive (e.g. `E:\threatpulse-vm\ThreatPulse-Lab`), **not C:** if C: is nearly full
- Encryption: **"Only the files needed to support a TPM are encrypted"**, and write down the password
- Disk: 80 GB, "Allocate all disk space now" **unchecked**, store as a single file
- Customize Hardware: **6144 MB memory, 4 cores, NAT network**

### 1.4 Install Windows in the VM

- Before starting the VM, run `wsl --shutdown` in Windows PowerShell to free RAM.
- Power on and press a key when asked to boot from the DVD. If you miss it, use **VM → Power → Restart Guest**.
- "Everything will be deleted" refers only to the VM's **empty virtual disk**, not your laptop.
- **Account screen: don't use your real Microsoft account.** Choose **Sign-in options → Domain join instead**, then create a local user `lab`.
- Privacy settings: turn **all** off.
- If setup starts downloading updates, let it finish.

### 1.5 Inside the VM

1. **VMware Tools:** click *Install Tools* in VMware. If it doesn't start, press **Win + R** in the VM and run `D:\setup64.exe` (Typical) → restart.
2. **Windows Update:** Settings → Windows Update → Check for updates. Repeat until "You're up to date".
3. **Git:** git-scm.com → Download for Windows → default options.
4. **Python 3.12:** python.org → Downloads → Windows.
   - Pick the newest **3.12.x** that still has a *"Windows installer (64-bit)"* link. Later 3.12 security releases have no installer.
   - Check **"Add python.exe to PATH"**.
   - If `python --version` fails but `py --version` works, rerun the installer → **Modify** → check *"Add Python to environment variables"*.
   - Turn off *python.exe* / *python3.exe* in **Settings → Apps → Advanced app settings → App execution aliases**.
5. **Sysmon with the `sysmon-modular` config:**
   - Download Sysmon from the Microsoft Sysinternals site (learn.microsoft.com, *Sysmon* page). Extract it to `C:\Tools\Sysmon`.
   - Download `sysmonconfig.xml` from github.com/olafhartong/sysmon-modular into the same folder.
   - In an **admin** PowerShell:
     ```
     cd C:\Tools\Sysmon
     .\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
     Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-Table TimeCreated, Id -AutoSize
     ```
   - The last command should list events. No LSASS (Event ID 10) events at this point is normal; that check happens in Phase 2.
6. **Lab marker file** (VM guard; enforcement code refuses to run without it). In the admin PowerShell:
   ```
   New-Item -ItemType Directory -Force C:\ThreatPulseLab
   Set-Content C:\ThreatPulseLab\LAB_VM "ThreatPulse lab VM - enforcement allowed only here"
   Test-Path C:\ThreatPulseLab\LAB_VM
   ```
   It should print `True`. **Never create this file on your real laptop.**
7. **Track A only:** Visual Studio Build Tools with "Desktop development with C++".

### 1.6 Lock down and snapshot

1. Shut down the VM.
2. **VM → Settings → Options**:
   - **Shared Folders: Disabled**
   - **Guest Isolation:** uncheck drag-and-drop and copy-and-paste

   You may turn copy-paste on temporarily during *setup* work, but it must be off during any simulation.
3. **VM → Snapshot → Take Snapshot**, named `clean-baseline`.
4. Test it: power on, create a file on the desktop, **Revert to Snapshot** → the file is gone.

---

## Part 2: WSL Ubuntu

Every command below runs in the **Ubuntu** terminal (prompt `user@host:~$`) unless it says *Windows PowerShell*.

### 2.1 Move WSL's disk off C: (if C: is low on space)

Ubuntu's disk is a file on C: by default, and `df -h` inside WSL shows its *maximum* size, not C:'s real free space. Only do this if the target drive is internal. In **Windows PowerShell**:
```
wsl -l -v
wsl --shutdown
mkdir E:\WSL
wsl --manage Ubuntu --move E:\WSL\Ubuntu
```
Use your distro's name from `wsl -l -v`. If `--manage` isn't recognized, run `wsl --update` first.

### 2.2 Stop WSL from seeing Windows programs

By default Ubuntu adds all Windows programs to its PATH. So `npm` may silently run the Windows version, and `powershell.exe` is reachable. To turn that off:
```
cat /etc/wsl.conf
```
If there is **no** `[interop]` section:
```
printf '\n[interop]\nappendWindowsPath=false\n' | sudo tee -a /etc/wsl.conf
```
Then run `wsl --shutdown` in Windows PowerShell, reopen Ubuntu, and check:
```
command -v npm || echo "npm: not found (good)"
command -v powershell.exe || echo "powershell: not found (good)"
```
Forgot your Ubuntu password? In Windows PowerShell run `wsl -d Ubuntu -u root`, then `passwd <yourusername>`, then `exit`.

### 2.3 Python 3.12 (with `uv`) and Node (with `nvm`)

Both install only in your home folder. No `sudo`, and don't use `sudo apt install python3.12/nodejs/npm`.
```
curl -LsSf https://astral.sh/uv/install.sh | sh
```
Reopen the terminal, then:
```
uv python install 3.12
uv run --python 3.12 python --version
```
For Node, copy the install command from the README at github.com/nvm-sh/nvm (`curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/<version>/install.sh | bash`). Reopen the terminal, then:
```
nvm install --lts
command -v npm
```
The path must start with `/home/...`, not `/mnt/c/...`.

### 2.4 VS Code with WSL

1. Install the **WSL** extension (by Microsoft) in VS Code on Windows.
2. Restore the `code` command, which 2.2 removed. Adjust the path if VS Code is installed elsewhere:
   ```
   echo 'function code { "/mnt/c/Users/<WindowsUser>/AppData/Local/Programs/Microsoft VS Code/bin/code" "$@"; }' >> ~/.bashrc
   source ~/.bashrc
   type code
   ```
   It should say `code is a function`. Don't use an `alias`: the spaces in the path break it.
3. The repo lives **inside WSL**, at `~/threatpulse`, never on `C:\` or `E:\`.
4. Open it with `code ~/threatpulse`, or click the `><` icon in VS Code → **Connect to WSL** → File → Open Folder.
5. The bottom-left corner must show **WSL: Ubuntu**. Without it, the VS Code terminal is PowerShell, and Ubuntu commands won't work there.
6. Workspace Trust: trust your own repo. Don't trust downloaded folders or datasets.

---

## Part 3: Claude Code (inside WSL only)

1. In a WSL terminal:
   ```
   curl -fsSL https://claude.ai/install.sh | bash
   ```
   Reopen the terminal, then run `claude --version`.
2. The repo's `.claude/settings.json` keeps Claude Code in **default (Manual) mode**, disables auto and bypass modes, and denies Windows programs, `/mnt/...` programs and `sudo`:
   ```json
   {
     "permissions": {
       "defaultMode": "default",
       "disableAutoMode": "disable",
       "disableBypassPermissionsMode": "disable",
       "deny": ["Bash(*.exe)", "Bash(*.exe *)", "Bash(/mnt/*)", "Bash(sudo *)"]
     }
   }
   ```
3. Start it from the repo (`cd ~/threatpulse && claude`), then check:
   - `/permissions` lists the deny rules.
   - Asking it to run `powershell.exe -Command Get-Date` is blocked.
4. Deny rules are **not a complete wall**: a command written in an unusual form can get past them. **Read every command before approving it.**
5. Don't use a Claude Code installed on the Windows host for this project.

---

## Checklist

- [ ] VM boots, `clean-baseline` snapshot exists and revert works
- [ ] In the VM: `git --version`, `python --version` (3.12.x), Sysmon logging, `Test-Path C:\ThreatPulseLab\LAB_VM` → True
- [ ] In WSL: `npm` and `powershell.exe` not found on the Windows PATH, `uv run --python 3.12 python --version` → 3.12.x, `command -v npm` → `/home/...`
- [ ] VS Code shows **WSL: Ubuntu**
- [ ] Claude Code runs in WSL, `/permissions` shows the deny rules, and the PowerShell test is blocked
