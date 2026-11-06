# Benign admin activity for recordings. Run ONLY inside the lab VM. Every command only reads
# system information. Attackers run some of these too, which is why they make useful benign
# data: the ML model must not treat ordinary admin work as an attack.

param([int]$Minutes = 10)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path 'C:\ThreatPulseLab\LAB_VM')) {
    throw 'Refusing to run: C:\ThreatPulseLab\LAB_VM not found. This script is for the lab VM only.'
}

$random = New-Object System.Random
$deadline = (Get-Date).AddMinutes($Minutes)
$tasks = @(
    { Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Out-Null },
    { Get-Service | Where-Object Status -eq 'Running' | Out-Null },
    { Get-NetIPConfiguration | Out-Null },
    { Get-HotFix | Out-Null },
    { Get-ChildItem C:\Windows\System32 -File | Measure-Object Length -Sum | Out-Null },
    { Get-WinEvent -LogName System -MaxEvents 50 | Out-Null },
    { Get-ScheduledTask | Out-Null },
    { & ipconfig /all | Out-Null },
    { & whoami /all | Out-Null },
    { & tasklist | Out-Null },
    { & netstat -ano | Out-Null },
    { & systeminfo | Out-Null }
)

while ((Get-Date) -lt $deadline) {
    & $tasks[$random.Next($tasks.Count)]
    Start-Sleep -Seconds $random.Next(5, 21)
}
