# Harmless test activity for the ThreatPulse agent. Run ONLY inside the lab VM, in a
# NEW PowerShell process started after the agent, so that this process counts as
# "started after agent". check_test_run.py then checks the recorded events.
#
# It uses dummy files in a dedicated test folder, and removes everything it creates.
# The "encryption" step only overwrites copies of dummy files with random bytes.
#
# It also makes one web request, which needs NAT on, and opens a handle to its own
# dummy ping process. It never touches LSASS: that check needs Atomic T1003.001 in
# step 2.3.

$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}

$folder = Join-Path $env:USERPROFILE 'Documents\ThreatPulseTest'
$fileCount = 25
$random = New-Object System.Random

New-Item -ItemType Directory -Force $folder | Out-Null

# Create dummy files.
for ($i = 1; $i -le $fileCount; $i++) {
    Set-Content (Join-Path $folder "dummy$i.txt") "ThreatPulse dummy file $i"
}

# The T1486 pattern on dummy files: write a scrambled copy, then delete the original.
for ($i = 1; $i -le $fileCount; $i++) {
    $bytes = New-Object byte[] 4096
    $random.NextBytes($bytes)
    [System.IO.File]::WriteAllBytes((Join-Path $folder "dummy$i.locked"), $bytes)
    Remove-Item (Join-Path $folder "dummy$i.txt")
}

# Rename.
Rename-Item (Join-Path $folder 'dummy1.locked') 'renamed.locked'

# A write after a rename must report the new name.
$stream = [System.IO.File]::Open((Join-Path $folder 'renamed.locked'), 'Open', 'Write')
$stream.Write([byte[]](1, 2, 3), 0, 3)
$stream.Dispose()

# Delete through FILE_DELETE_ON_CLOSE, which does not produce event 26.
$stream = New-Object System.IO.FileStream(
    (Join-Path $folder 'delete-on-close.tmp'), 'Create', 'Write', 'None', 4096, 'DeleteOnClose')
$stream.Write([byte[]](1, 2, 3), 0, 3)
$stream.Dispose()

# Run and RunOnce keys: added and removed straight away.
foreach ($name in 'Run', 'RunOnce') {
    $key = "HKCU\Software\Microsoft\Windows\CurrentVersion\$name"
    & reg add $key /v ThreatPulseTest /t REG_SZ /d C:\Windows\System32\notepad.exe /f | Out-Null
    & reg delete $key /v ThreatPulseTest /f | Out-Null
}

# Clean up. The folder itself must not be reported as a file_delete.
Remove-Item -Recurse $folder

# A network connection from this process. A failure is only a warning, so the checks
# for everything else can still run, and check_test_run.py reports the missing event.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest 'https://example.com' -UseBasicParsing -TimeoutSec 20 | Out-Null
} catch {
    Write-Warning "The web request failed, so the network checks will fail: $_"
}

# ProcessAccess on a dummy process, to prove the mask is decoded. sysmon-modular logs
# 0x21410 for any target. The handle includes vm_read, but nothing is ever read from it.
$signature = @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
'@
$native = Add-Type -MemberDefinition $signature -Name 'ProcessHandle' -Namespace 'ThreatPulseTest' -PassThru
$dummy = Start-Process 'ping' -ArgumentList '-n 6 127.0.0.1' -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 1
$handle = $native::OpenProcess([uint32]0x21410, $false, [uint32]$dummy.Id)
if ($handle -eq [IntPtr]::Zero) {
    Write-Warning 'Could not open the dummy process, so the process_access check will fail.'
} else {
    [void]$native::CloseHandle($handle)
}
Stop-Process -Id $dummy.Id -ErrorAction SilentlyContinue

$pidFile = 'C:\ThreatPulseLab\logs\test_pid.txt'
Set-Content $pidFile $PID
"Test activity finished. Test process ID: $PID (saved to $pidFile)"
