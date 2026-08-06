# Malware Analysis Report: Xarid-Stealer

**Classification:** Trojan Dropper / Downloader  
---

## File Metadata

| Property | Value |
|----------|-------|
| **Filename** | `Xarid-Stealer__0133a8a0bc4521eb.jar` |
| **Size** | 23,127 bytes (22.6 KB) |
| **MD5** | `123a1b6770606b2dd2bce6b143387106` |
| **SHA1** | `f27e28d854ad1d4cdd494a660614aef744e1eceb` |
| **SHA256** | `0133a8a0bc4521eb39f24563c0866fe93eb0501507a920abbae5692f60c89220` |
| **Main Class** | `MoliyaviyTahlilIlovasi` |
| **JAR Structure** | 1 class file + 3 binary data files + manifest |

---

## JAR Contents

```
META-INF/MANIFEST.MF              — Manifest (Main-Class: MoliyaviyTahlilIlovasi)
MoliyaviyTahlilIlovasi.class      — Primary malicious logic (11,463 bytes, Java 1.8)
.data_534.dat                     — Encrypted/obfuscated binary data (8,192 bytes)
.cache_13.dat                     — Encrypted/obfuscated text data (8,192 bytes)
.tmp_359.dat                      — Encrypted/obfuscated binary data (2,048 bytes)
```

The three `.dat` files are binary/text blobs that appear to be encrypted or encoded payloads. The `.cache_13.dat` file contains high entropy random ASCII data consistent with encrypted content. These files are not directly referenced by the decompiled Java code, suggesting they may be loaded via reflection or accessed by the downloaded second stage payloads.

---

## Execution Flow

```
[User opens JAR]
       
       v
[1] Show fake Uzbek tax inspection dialog
       
       v
[2] User clicks "QABUL QILINDI" (Accepted)
       
       v
[3] Check execution counter (max 6 runs)
       
       v
[4] Contact C2 server: http://my-xarid.com/api/v5/
       
       v
[5] Download 20 malicious components to %USERPROFILE%\Documents\MoliyaviyTahlil\BuxgalteriyaHisobot\AnalizModuli\
      
       v
[6] Create loader batch file (moliyaviy_tahlil_loader.bat)
       
       v
[7] Execute client32.exe via cmd.exe
       
       v
[8] Create persistence in Startup folder
       
       v
[9] Add Registry Run key for persistence
```

---

## Social Engineering Component

The malware employs a social engineering technique in the **Uzbek language**, targeting users in Uzbekistan:

- **Window Title:** "Moliyaviy Tahlil - Buxgalteriya Ilovasi" (Financial Analysis - Accounting Application)
- **Content:** A fake tax inspection warning claiming that "serious irregularities" were found in the organization's financial activity during tax reporting analysis.
- **Threat Narrative:** Warns the user that if they don't act, a tax inspection decision may be made. It tells them the application "doesn't work on this computer" and instructs them to open it on another computer.
- **Call to Action:** A green button labeled "QABUL QILINDI" (Accepted) that dismisses the dialog and triggers the malware payload.

The class name `MoliyaviyTahlilIlovasi` translates to "FinancialAnalysisApplication" in Uzbek. The internal variable names are all in Uzbek, indicating the author is a native Uzbek speaker.

---

## Technical Analysis

### 1. Command & Control Server

| Property | Value |
|----------|-------|
| **C2 URL** | `http://my-xarid.com/api/v5/` |
| **Protocol** | HTTP (unencrypted) |
| **User-Agent** | `Moliyaviy-Tahlil-Agent` |
| **Connect Timeout** | 3,450 ms |
| **Read Timeout** | 4,950 ms |
| **Download Timeout** | Connect: 6,100 ms / Read: 10,200 ms |

The domain `my-xarid.com` translates to "my-order.com" in Uzbek. The server check accepts both HTTP 200 and HTTP 403 responses as "online," suggesting the API may use 403 as a valid response code (e.g., to block non agent requests while still serving the malware).

### 2. Dropped Payloads (20 Components)

The malware downloads **20 files** from the C2 server to the directory:

```
%USERPROFILE%\Documents\MoliyaviyTahlil\BuxgalteriyaHisobot\AnalizModuli\
```

| File | Notes |
|------|-------|
| `client32.exe` | **Primary payload executor** - launched via batch loader |
| `remcmdstub.exe` | Likely a remote command stub - name suggests remote access capability |
| `PCICL32.dll` | Malicious DLL |
| `pcicapi.dll` | Malicious DLL |
| `NSM.lic` | License file - possibly configuration or encrypted data |
| `nskbfltr.inf` | Malicious driver inf file |
| `ir50_32.dll` | DLL (name impersonates Intel IR driver) |
| `kbd106n.dll` | Keyboard DLL (name impersonates keyboard driver) |
| `kbd101c.DLL` | Keyboard DLL (name impersonates keyboard driver) |
| `kbdibm02.DLL` | Keyboard DLL (name impersonates keyboard driver) |
| `HTCTL32.DLL` | DLL (name impersonates HotKey control) |
| `tcctl32.dll` | DLL (name impersonates TrueCrypt control) |
| `KBDSF.DLL` | Keyboard DLL |
| `kbdlk41a.dll` | Keyboard DLL |
| `AudioCapture.dll` | **Audio capture component** - likely for microphone recording |
| `client32.ini` | Configuration file for client32.exe |
| `ir50_qcx.dll` | DLL (impersonates IR driver) |
| `msvcr100.dll` | DLL (impersonates Visual C++ runtime) |
| `advpack.dll` | DLL (impersonates Windows Advanced Packaging) |
| `PCICHEK.DLL` | Malicious DLL |

**Key observations:**
- Several DLLs impersonate legitimate Windows keyboard drivers (`kbd*.dll`) - this is consistent with a **keylogger** component.
- `AudioCapture.dll` strongly suggests **audio/microphone surveillance** capability.
- `remcmdstub.exe` suggests **remote command execution** capability.
- `client32.exe` appears to be the main second-stage payload.
- Names impersonating legitimate system files (`msvcr100.dll`, `advpack.dll`) could be used to evade detection or hijack DLL loading.

### 3. Persistence Mechanisms

The malware establishes **two independent persistence mechanisms** to survive reboots:

#### Startup Folder
```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\moliyaviy_tahlil_avto.bat
```
Content: A batch file that silently launches the loader in the background.

#### Windows Registry
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value Name: MoliyaviyTahlil
Value Data: "<path_to_loader_batch_file>"
```
Executed via `reg add` command through `cmd.exe`.

### 4. Execution Counter

The malware maintains a run counter in:
```
%USERPROFILE%\Documents\MoliyaviyTahlil\BuxgalteriyaHisobot\ruxsatnoma.dat
```
- Maximum of **6 executions** allowed
- After 6 runs, the malware silently stops executing (returns without downloading)

### 5. Loader Mechanism

```
%USERPROFILE%\Documents\MoliyaviyTahlil\BuxgalteriyaHisobot\AnalizModuli\moliyaviy_tahlil_loader.bat
```
```batch
@echo off
cd /d "%~dp0"
start "" /B "client32.exe"
exit
```
Executed via:
```
cmd.exe /c start "" /B "<path_to_loader>"
```

### 6. Anti Analysis Techniques

| Technique | Description |
|-----------|-------------|
| **Execution limit (6 runs)** | Limits exposure in sandbox environments |
| **Random delays** | 22–47ms between downloads to evade time based detection |
| **Empty catch blocks** | Silently swallows all exceptions to avoid crash detection |
| **Multiple benign looking filenames** | Uses names of legitimate Windows system files |
| **Hidden directory** | Drops payloads in an obscure Documents subdirectory |
| **Binary data files** | `.dat` files in JAR likely contain encrypted configs/payloads |

---

## Indicator of Compromise (IOCs)

### Network IOCs
```
Domain:     my-xarid.com
URL Path:   /api/v5/
Full URL:   http://my-xarid.com/api/v5/
User-Agent: Moliyaviy-Tahlil-Agent
User-Agent: MoliyaviyTahlil/1.0
```

### File IOCs
```
Directory:  %USERPROFILE%\Documents\MoliyaviyTahlil\
Subdirs:    BuxgalteriyaHisobot\AnalizModuli\
Files:
  ruxsatnoma.dat                          (execution counter)
  moliyaviy_tahlil_loader.bat             (loader)
  moliyaviy_tahlil_avto.bat               (startup persistence)
  client32.exe                            (main payload)
  remcmdstub.exe                          (remote access stub)
  AudioCapture.dll                        (audio surveillance)
  qwave.dll, PCICL32.dll, pcicapi.dll     (malicious DLLs)
  NSM.lic, nskbfltr.inf                   (config/driver)
  ir50_32.dll, ir50_qcx.dll               (driver impersonation)
  kbd106n.dll, kbd101c.DLL, kbdibm02.DLL (keylogger impersonation)
  HTCTL32.DLL, tcctl32.dll, KBDSF.DLL    (malicious DLLs)
  kbdlk41a.dll                            (malicious DLL)
  client32.ini                            (payload config)
  msvcr100.dll, advpack.dll               (DLL hijacking)
  PCICHEK.DLL                             (malicious DLL)
```

### Registry IOCs
```
Key:   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: MoliyaviyTahlil
Data:  "<path_to_loader_bat>"
```

### Hash IOCs
```
MD5:    123a1b6770606b2dd2bce6b143387106
SHA1:   f27e28d854ad1d4cdd494a660614aef744e1eceb
SHA256: 0133a8a0bc4521eb39f24563c0866fe93eb0501507a920abbae5692f60c89220
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Initial Access | Masquerading | T1078.002 | JAR file disguised as financial analysis tool |
| Initial Access | Spearphishing Attachment | T1566.001 | Delivered as email attachment targeting Uzbek speakers |
| Execution | Java | T1059.005 | Primary payload executed via Java |
| Execution | Command Scripting | T1059.003 | Uses cmd.exe and .bat files for execution |
| Execution | Windows Management Instrumentation | T1047 | Uses ProcessBuilder for command execution |
| Persistence | Registry Run Keys | T1547.001 | Adds Run key for auto-start |
| Persistence | Startup Items | T1547.001 | Places batch file in Startup folder |
| Defense Evasion | Obfuscated Files | T1027.003 | Binary .dat files with encrypted payloads |
| Defense Evasion | Masquerading | T1036.001 | Uses legitimate Windows system file names |
| Defense Evasion | Indicator Removal | T1070.004 | Empty catch blocks hide errors |
| Command & Control | Application Layer Protocol | T1071.001 | HTTP C2 communication |
| Discovery | System Information Discovery | T1082 | Checks USERPROFILE, APPDATA environment |
| Impact | Fraudulent Software | T1656 | Fake financial analysis application |

---

## Capability Assessment

Based on the dropped components behavioral patterns, this malware likely provides the following capabilities:

| Capability | Evidence | 
|------------|----------|
| **Keylogging** | Multiple `kbd*.dll` files impersonating keyboard drivers |
| **Audio Surveillance** | `AudioCapture.dll` component | 
| **Remote Access** | `remcmdstub.exe` (remote command stub) | 
| **Data Exfiltration** | HTTP C2 channel with active downloads | 
| **Persistence** | Dual persistence (Startup + Registry) | 
| **Credential Theft** | "Stealer" in filename; full component set suggests credential harvesting | 
| **Screen Capture** | `client32.exe` with associated DLLs |

---

## Detection & Removal

### Detection
1. **Check for existence of directory:** `%USERPROFILE%\Documents\MoliyaviyTahlil\`
2. **Check startup folder:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\moliyaviy_tahlil_avto.bat`
3. **Check registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for value `MoliyaviyTahlil`
4. **Network monitoring:** Block domain `my-xarid.com`
5. **YARA rule:**
```
rule XaridStealer {
    strings:
        $class = "MoliyaviyTahlilIlovasi"
        $c2 = "my-xarid.com"
        $ua1 = "Moliyaviy-Tahlil-Agent"
        $ua2 = "MoliyaviyTahlil/1.0"
        $path = "MoliyaviyTahlil"
        $reg = "MoliyaviyTahlil"
    condition:
        uint16(0) == 0x4A50 and
        2 of ($class, $c2, $ua1, $ua2) or
        all of ($path, $reg)
}
```

### Removal Steps
1. Delete the entire directory `%USERPROFILE%\Documents\MoliyaviyTahlil\`
2. Delete `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\moliyaviy_tahlil_avto.bat`
3. Remove registry key: `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v MoliyaviyTahlil /f`
4. Check Task Manager for running `client32.exe` or `remcmdstub.exe` processes and terminate them
5. Block domain `my-xarid.com` at firewall/DNS level
6. Run a full antivirus scan and consider credential reset (passwords, tokens, etc.)

---

## Conclusion

`Xarid-Stealer` is a **trojan dropper** that uses Uzbek language social engineering to deceive targets into running what appears to be an official tax inspection tool. It downloads and executes a multi component second stage payload capable of keylogging, audio capture, remote access, and credential theft, while establishing persistence mechanisms. The use of local language, fake government themed warnings, execution limits, and system file name impersonation indicates a targeted attack campaign against Uzbek speaking users.

---
-thank you for reading
