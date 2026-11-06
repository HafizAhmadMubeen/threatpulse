# VM test plan: scan_file

These are the Gate 1 checks that need Windows (PHASES.md steps 1.5 to 1.7). **Run everything here inside the lab VM, by hand. Never run any of it on the host.** That applies most of all to the Defender exclusion and the EICAR file.

Nothing here leaves the VM: write the results in the table at the end by hand.

## 1. Prepare

1. Turn off shared folders and the shared clipboard.
2. Take a snapshot called `pre-scan-test`. Step 6 rolls back to it, which removes the exclusion and everything else.
3. Keep NAT on for now, for steps 2 and 4. Turn it off afterwards if you like.

In PowerShell, from `C:\ThreatPulseLab\threatpulse`:

```powershell
git fetch origin
git checkout track-b/signatures
py -3.12 -m venv .venv-detection
.venv-detection\Scripts\python -m pip install yara-python==4.5.4 pefile==2024.8.26 "jsonschema>=4.26.0"
```

Check that it's 64-bit Python, and that it's the VM. This must print `AMD64` and `True`:

```powershell
.venv-detection\Scripts\python -c "import platform, os; print(platform.machine(), os.path.exists(r'C:\ThreatPulseLab\LAB_VM'))"
```

## 2. Test folder and Defender exclusion

**Only inside the VM, and in an Administrator PowerShell.** The exclusion covers this one empty folder and nothing else.

```powershell
New-Item -ItemType Directory -Force C:\ThreatPulseLab\scan-test
Add-MpPreference -ExclusionPath C:\ThreatPulseLab\scan-test
(Get-MpPreference).ExclusionPath
```

## 3. Marker file

```powershell
[IO.File]::WriteAllBytes('C:\ThreatPulseLab\scan-test\marker.txt', [Text.Encoding]::ASCII.GetBytes('THREATPULSE-TEST-MARKER'))
.venv-detection\Scripts\python -m detection C:\ThreatPulseLab\scan-test\marker.txt
```

**Expected:** `hash_match` is `TEST-MARKER`, `yara_matches` has `ThreatPulse_Test_Marker`, and there's one alert with `rule_id` `SIG-TEST-MARKER`.

## 4. EICAR (Gate 1)

This plan doesn't include the EICAR string, on purpose.

1. In the VM's browser, open `https://www.eicar.org` and find the test file string.
2. Paste it into Notepad as one line, with nothing else in the file.
3. Save it as `C:\ThreatPulseLab\scan-test\eicar.com`. Set "Save as type" to "All files", and use ANSI or UTF-8 without BOM. The file should be 68 bytes.

```powershell
(Get-Item C:\ThreatPulseLab\scan-test\eicar.com).Length
.venv-detection\Scripts\python -m detection C:\ThreatPulseLab\scan-test\eicar.com
```

**Expected:**
- `sha256` is `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
- `hash_match` is `EICAR`
- `yara_matches` has `EICAR_Test_File`
- There's **one** alert, with `rule_id` `SIG-EICAR`, whose `static_analysis.reasons` lists both `SHA-256 match` and `YARA rule EICAR_Test_File`

If the size is wrong, the hash won't match, and it's usually a BOM or a trailing newline. Save it again rather than changing the rule. This is the first real test of the EICAR YARA rule, because it can't be tested outside the VM.

## 5. UPX: packed scores higher than the original (Gate 1)

UPX refuses many Windows system binaries, so use a small program of our own. In a Developer Command Prompt for Visual Studio:

```bat
cd C:\ThreatPulseLab\scan-test
echo #include ^<stdio.h^> > hello.c
echo int main(void) { puts("hello"); return 0; } >> hello.c
cl /nologo /O2 hello.c
hello.exe
```

Download UPX from `https://github.com/upx/upx/releases` (the `win64` zip) and unzip it into `C:\ThreatPulseLab\upx`. Then, in PowerShell:

```powershell
cd C:\ThreatPulseLab\scan-test
C:\ThreatPulseLab\upx\upx.exe -o hello_upx.exe hello.exe
cd C:\ThreatPulseLab\threatpulse
.venv-detection\Scripts\python -m detection C:\ThreatPulseLab\scan-test\hello.exe C:\ThreatPulseLab\scan-test\hello_upx.exe
```

**Expected:**
- `hello.exe`: `heuristics.score` is low (0 to 0.25), with no alerts
- `hello_upx.exe`: `heuristics.score` is **higher**, at 0.50 or more, with one alert with `rule_id` `HEUR-UPX-PACKED`, and reasons naming `UPX0` and `UPX1`

The gate passes if the packed score is higher than the original.

## 6. Clean up

Roll back to `pre-scan-test`. That removes the exclusion, EICAR, UPX and the test programs. Don't copy anything out of the VM first.

## Results

| Check | Expected | Actual | Pass? |
|---|---|---|---|
| Marker: hash | `TEST-MARKER` | | |
| Marker: YARA | `ThreatPulse_Test_Marker` | | |
| EICAR: hash | `EICAR` | | |
| EICAR: YARA | `EICAR_Test_File` | | |
| EICAR: alerts | 1, `SIG-EICAR`, both reasons | | |
| `hello.exe` score | Low, no alert | | |
| `hello_upx.exe` score | Higher, 0.50 or more | | |
| Rolled back to `pre-scan-test` | Yes | | |

If a score looks wrong, send the reasons from the output, not the files. Only `.jsonl` and `.csv` logs may leave the VM (PLANNING.md Section 3.2).
