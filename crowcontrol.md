# Malware Analysis of "CrowControl" Remote Access Trojan.

This report provides a detailed technical analysis of the CrowControl malware sample. The analysis covers its
PyInstaller based installation process, WebSocket command-and-control, credential theft,
remote access functionality, surveillance features, fake application presets, and anti
analysis mechanisms. The sample is a Windows Remote Access Trojan (RAT) and credential stealer designed to
establish persistent unauthorized remote control over compromised systems.

The supplied agent source was extracted from a PyInstaller compiled executable. A separate
decompilation and analysis of embedded modules such as `grabber.pyc` confirms theft of Google Chrome saved
passwords and Discord authentication tokens.

---

## 1. Executive Summary

The analyzed CrowControl sample is a Python based Windows Remote Access Trojan distributed as a PyInstaller
executable, Although CrowControl may also come in Jar files, sadly at the time of this analysis I did not have a JAR sample due to them being available for only paid memberships.
The malware establishes a WebSocket connection to a configurable command-and-control server and
provides the operator with interactive control over the infected machine.

The hardcoded C2 endpoint for this MaaS is:

```
ws://manage.gleeze.com:3000
```

After connecting, the agent sends a `register_agent` message containing the victim's hostname, operating system,
screen resolution, monitor information, startup status, public IP address, geographical information, persistent
device identifier, and a builder assigned `userToken`.

CrowControl provides screen streaming, remote mouse and keyboard input, CMD and PowerShell command execution,
file browsing and exfiltration, file upload, process listing and termination, webcam capture, microphone capture,
keylogging, Chrome password theft, Discord token theft, live chat, wallpaper changes,
audio playback, system shutdown/restart, application blocking, and remote self deletion.

The malware also contains a strong persistence mechanism. When running as a frozen PyInstaller executable it
copies itself into a hidden `%LOCALAPPDATA%` directory under a system like name, creates a hidden backup copy,
deploys a VBScript watchdog, registers a hidden Scheduled Task, and adds a registry Run-key fallback. The
watchdog is designed to restore the executable if it is deleted and restart the malware if the process is killed.

CrowControl includes multiple fake application presets intended to disguise the initial execution and make it seem like a legitimate software.
These include a cheat client, cracked software installer, Discord Nitro generator, PC optimizer, cryptocurrency brute-forcer,
skin changer, fake hacking tool, GTA VI downloader, and Minecraft modpack installer.

---

## 2. File Metadata and Indicators of Compromise

### 2.1 Sample Information

| Item | Value |
|---|---|
| Malware Family | `CrowControl` |
| Classification | `Remote Access Trojan / Credential Stealer` |
| Platform | `Windows` |
| Language | `Python` |
| Packaging | `PyInstaller executable` |
| Agent Source | `agent.pyc` |
| Grabber Module | `grabber.pyc` |
| Agent Source Size | `119,658 bytes` |
| Agent Source Lines | `2,360` |
| Default C2 | `ws://manage.gleeze.com:3000` |
| Default C2 Port | `3000/TCP` |
| Startup Task | `CrowControlAgent` |

### 2.2 Host and Network IOCs

| Indicator | Type | Purpose |
|---|---|---|
| `ws://manage.gleeze.com:3000` | Network | Default WebSocket C2 |
| `manage.gleeze.com` | Domain | Default C2 hostname |
| `3000/TCP` | Port | Default C2 port |
| `CrowControlAgent` | Scheduled Task | Startup persistence |
| `svc_helper.vbs` | File | Watchdog script |
| `_svchlp.xml` | File | Temporary task XML |
| `CrowControl_task.xml` | File | Startup task XML |
| `cc_cleanup.bat` | File | Self deletion script |
| `%APPDATA%\CrowControl\device.id` | File | Persistent device identifier |
| `%LOCALAPPDATA%\RealtekAudioPlayer\blocked_apps.json` | File | AppBlocker state |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Registry | Persistence fallback |
| `127.0.0.1:29847` | Local Socket | Single instance mechanism |

### 2.3 Disguised Identities

CrowControl can install itself using several system-like identities.

| Executable | Directory / Task Identity |
|---|---|
| `EdgeUpdate.exe` | `MicrosoftEdgeUpdate` |
| `GoogleCrashHandler.exe` | `GoogleCrashReporter` |
| `RealtekHDAudio.exe` | `RealtekHDAudioService` |
| `IntelRSTService.exe` | `IntelRapidStorageTech` |
| `NVDisplay.Container.exe` | `NVDisplayContainer` |
| `OneDriveStandaloneUpdater.exe` | `OneDriveService` |
| `MsMpEng.exe` | `WindowsDefenderSvc` |
| `DiscordUpdater.exe` | `DiscordService` |
| `SteamService.exe` | `SteamClientService` |
| `AdobeARM.exe` | `AdobeUpdateManager` |

The Scheduled Task name can be formed by appending `Watchdog`, for example
`MicrosoftEdgeUpdateWatchdog`, `GoogleCrashReporterWatchdog`, or `WindowsDefenderSvcWatchdog`.

---

## 3. Execution Flow

CrowControl implements a multi stage installation and execution flow. The visible executable may display a fake
application interface while a copied background agent is installed and launched separately.

### 3.1 Stage 1: PyInstaller Entry Point

The main entry point checks:

```python
getattr(sys, "frozen", False)
```

and references `sys._MEIPASS`, both standard PyInstaller runtime artifacts.

The agent supports:

```text
--server
--no-admin-check
--boot-delay
--skip-preset
```

### 3.2 Stage 2: Hidden Installation

The malware selects one of its disguised identities and creates an installation under `%LOCALAPPDATA%`.

```text
%LOCALAPPDATA%\MicrosoftEdgeUpdate\EdgeUpdate.exe
%LOCALAPPDATA%\MicrosoftEdgeUpdate\.sys\EdgeUpdate.exe
%LOCALAPPDATA%\MicrosoftEdgeUpdate\.sys\svc_helper.vbs
```

The executable is copied into both the main path and the hidden `.sys` backup directory. The directories and
files are assigned hidden/disguised attributes to reduce visibility.

### 3.3 Stage 3: Watchdog and Persistence

The generated `svc_helper.vbs` watchdog waits after launch, checks if the main executable still exists, restores
it from the backup if necessary, queries WMI for the malware process, and relaunches the agent when it is no
longer running.

A hidden Scheduled Task executes:

```
wscript.exe //B //Nologo "%LOCALAPPDATA%\MicrosoftEdgeUpdate\.sys\svc_helper.vbs"
```

The task contains a logon trigger and a repeating time trigger. CrowControl additionally writes a fallback value
under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

A separate startup helper creates the task `CrowControlAgent` and launches the agent with:

```text
--no-admin-check --skip-preset
```

### 3.4 Stage 4: C2 Registration

The background agent connects to the configured WebSocket server and sends:

```text
register_agent
```

with fields including:

```text
deviceId
hostname
os
resolution
startup
userToken
monitor_count
monitors
ip
country
country_code
city
lat
lng
```

The embedded `USER_TOKEN` is UUID formatted and is sent inside the WebSocket registration JSON.

After registration the malware waits for JSON commands and dispatches them to its RAT functions.

---

## 4. Social Engineering and Fake Application Presets (trojan)

CrowControl contains multiple fake application interfaces that can be selected through the builder. These
interfaces simulate real software behavior while the RAT executes in the background.

| Preset | Disguise |
|---|---|
| `hackingclient` | Cheat / hacking client |
| `crackedsoftware` | Cracked software installer |
| `nitrogenerator` | Discord Nitro generator |
| `pcoptimizer` | PC optimizer |
| `cryptobrute` | Cryptocurrency brute-forcer |
| `skinchanger` | Game skin changer |
| `skidtool` | Fake hacking utility |
| `gta6downloader` | GTA VI downloader |
| `minecraftmodpack` | Minecraft modpack installer |

The supplied configuration contains:

```text
PRESET_TYPE = none
PRESET_GAME = Fortnite
PRESET_SOFTWARE = AimBot Pro
PRESET_THEME = matrix
```

The cheat client displays fake initialization, license validation, and fabricated anti-cheat/injection errors.
The Nitro generator creates random `discord.gift/...` strings and labels them as valid or invalid. The crypto
preset fabricates BTC, ETH, and SOL wallet balances. Other presets simulate installation, downloading,
optimization, or mod setup.

This design allows different CrowControl builds to appear unrelated even though they share the same underlying
RAT code and C2 protocol.

---

## 5. Credential Theft

The recovered `grabber.pyc` module confirms direct credential theft. The agent remotely invokes:

```python
grabber.grab_all()
```

after receiving the command:

```text
grab_tokens
```

and returns the data through the existing WebSocket as:

```text
grabbed_tokens
```

The grabber returns:

```python
{
    "passwords": grab_chrome_passwords(),
    "discord_tokens": grab_discord_tokens()
}
```

### 5.1 Chrome Password Theft

CrowControl reads:

```text
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Local State
```

to obtain Chrome's `os_crypt.encrypted_key`.

It then targets:

```text
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\default\Login Data
```

The database is copied into the temporary directory as:

```text
ChromeData.db
```

and queried with:

```sql
SELECT origin_url, username_value, password_value FROM logins
```

The malware uses Windows `CryptUnprotectData` and contains an AES-GCM decryption path for Chromium protected
password values.

Recovered entries contain:

```text
url
username
password
```

### 5.2 Discord Token Theft

CrowControl searches Discord and Chromium data for authentication tokens.

paths include:

```text
%APPDATA%\discord
%APPDATA%\discordcanary
%APPDATA%\Lightcord
%APPDATA%\discordptb
%APPDATA%\Opera Software\Opera Stable
%APPDATA%\Opera Software\Opera GX Stable
%LOCALAPPDATA%\Amigo\User Data
%LOCALAPPDATA%\Torch\User Data
%LOCALAPPDATA%\Kometa\User Data
%LOCALAPPDATA%\Orbitum\User Data
%LOCALAPPDATA%\CentBrowser\User Data
%LOCALAPPDATA%\7Star\Sputnik\Default
%LOCALAPPDATA%\Vivaldi\Default
```

The decompiled path list is truncated after the Vivaldi entry, so the original bytecode may contain additional
targets.

For each application CrowControl searches:

```text
Local Storage\leveldb
```

and reads `.ldb` and `.log` files looking for:

```text
dQw4w9WgXcQ:
```

The matched Base64 data is decrypted using the application's Chromium encryption key when available.

### 5.3 Credential Exfiltration

The grabber does not contain a separate exfiltration service. Stolen passwords and tokens are returned through
the CrowControl WebSocket C2. For this build the default destination is:

```text
ws://manage.gleeze.com:3000
```

---

## 6. Remote Access and Surveillance 

CrowControl provides command surface for interactive remote access.

| Capability | Implementation |
|---|---|
| Screen Capture | Windows GDI + `mss` |
| Mouse / Keyboard | `pyautogui` |
| Webcam | OpenCV `VideoCapture` |
| Microphone | PyAudio |
| Keylogging | External `keylogger` module |
| CMD Shell | `cmd.exe /c` |
| PowerShell Shell | `powershell.exe -ExecutionPolicy Bypass` |
| File Browser | List/download/upload/delete/rename |
| Folder Theft | ZIP archive returned over C2 |
| Process Control | `psutil` process listing and killing |
| System Information | CPU/RAM/disk/network/OS/user/IP/geo |
| Live Chat | Tkinter chat window |
| App Blocking | Repeated process termination |
| Shutdown / Restart | Windows shutdown commands |
| Wallpaper | `SystemParametersInfoW` |
| Audio | Windows Media Player COM via PowerShell |
| Message Boxes | `MessageBoxW` |
| Self Destruct | Removes persistence and deletes files |

### 6.1 Screen and Input Control

CrowControl uses Windows GDI functions such as:

```text
GetDC
CreateCompatibleDC
CreateCompatibleBitmap
BitBlt
GetDIBits
DrawIconEx
```

and also uses `mss` for screen capture. Frames are converted to JPEG and sent through the C2.

Relevant values include:

```text
CAPTURE_FPS = 12
JPEG_QUALITY = 45
MAX_FRAME_W = 1280
MAX_FRAME_H = 720
SCREEN_FPS = 12
SCREEN_QUALITY = 50
```

Remote input is performed with `pyautogui`, supporting mouse movement, clicking, scrolling, key presses, and
typing. The sample disables PyAutoGUI's normal fail-safe:

```python
pyautogui.FAILSAFE = False
```

### 6.2 Webcam and Microphone

The webcam is opened with:

```python
cv2.VideoCapture(0, cv2.CAP_DSHOW)
```

and frames are JPEG encoded before being Base64 encoded and sent as `webcam_frame`.

The microphone stream uses 16-bit mono PCM at 16 kHz and sends Base64 encoded chunks as:

```text
mic_chunk
```

### 6.3 Remote Shell and Files

CMD commands execute through:

```text
cmd.exe /c <command>
```

and a PowerShell path uses:

```text
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <command>
```

File operations include:

```text
fs_list
fs_download
fs_download_folder
fs_delete
fs_rename
fs_upload
```

The maximum configured file size is 256 MiB.

---

## 7. Network Communication Indicators

CrowControl uses a WebSocket based C2 protocol with JSON messages.

### 7.1 Default C2

```text
ws://manage.gleeze.com:3000
```

The use of `ws://` rather than `wss://` means the default configuration does not request TLS for the WebSocket
connection.

### 7.2 C2 Data Types

The same connection is used for registration, commands, and stolen data.

Observed message strings include:

```text
register_agent
registered
grabbed_tokens
keylogger_data
webcam_frame
mic_chunk
terminal_output
fs_file_data
ps_list_data
sys_info_data
```

Binary data such as screenshots, webcam frames, files, and microphone chunks is commonly Base64 encoded before
being placed into JSON. Base64 is encoding rather than encryption.

### 7.3 Operator Commands

```text
audio_play
audio_play_data
audio_stop
chat_close
chat_message
chat_open
fs_delete
fs_download
fs_download_folder
fs_list
fs_rename
fs_upload
get_blocked_apps
get_monitors
get_startup_status
grab_tokens
input
keylogger_start
keylogger_stop
mic_start
mic_stop
open_url
ps_kill
ps_list
rdp_key
rdp_mouse
rdp_start
rdp_stop
rdp_type
restart
self_destruct
set_blocked_apps
set_startup
set_wallpaper
show_msgbox
shutdown
stream_mode
subscribe
switch_monitor
sys_info
terminal_close
terminal_input
terminal_open
unsubscribe
webcam_start
webcam_stop
```

### 7.4 Public IP / Geolocation Services

CrowControl also contacts:

```
http://ip-api.com/json/
https://ipapi.co/json/
https://api.ipify.org
```

---

## 8. Anti Analysis and Evasion Techniques


| Technique | Implementation | Effect |
|---|---|---|
| **VM System Checks** | WMI manufacturer/model/BIOS strings | Detects common virtual machines |
| **VM Registry Checks** | VMware, VirtualBox and Microsoft VM keys | Detects guest tools |
| **VM Process Checks** | `vmtoolsd.exe`, `vboxservice.exe`, `qemu-ga.exe`, etc. | Detects analysis environments |
| **Analysis Process Checks** | Includes `wireshark.exe` and sandbox process names | Avoids monitored systems |
| **MAC OUI Checks** | VMware, VirtualBox, Hyper-V, QEMU prefixes | Detects virtual NICs |
| **Resource Checks** | Low CPU and RAM heuristic | Detects lightweight sandboxes |
| **Masquerading** | Microsoft/Google/Realtek/NVIDIA/etc. names | Blends into AppData |
| **Hidden Files** | Hidden/system attributes | Reduces visibility |
| **Silent Exceptions** | Broad exception swallowing | Hides failures |
| **Fake Application UI** | Configurable decoy software | Social engineering |
| **PyInstaller Packaging** | Bundles Python runtime and modules | Complicates casual inspection |
| **Watchdog Recovery** | Restores/restarts deleted or killed agent | Increases persistence |

---

## 9. MITRE ATT&CK Mapping

| Technique | ID | CrowControl Behavior |
|---|---|---|
| User Execution: Malicious File | `T1204.002` | Fake applications encourage execution |
| Masquerading | `T1036` | System-like executable and directory names |
| PowerShell | `T1059.001` | Remote PowerShell execution |
| Windows Command Shell | `T1059.003` | CMD execution and cleanup batch |
| Visual Basic | `T1059.005` | VBScript watchdog |
| Scheduled Task | `T1053.005` | Hidden logon/repeating persistence |
| Registry Run Keys | `T1547.001` | HKCU Run fallback |
| Hidden Files and Directories | `T1564.001` | Hidden install and backup |
| Virtualization/Sandbox Evasion | `T1497.001` | VM checks |
| Process Discovery | `T1057` | Process enumeration |
| System Information Discovery | `T1082` | CPU/RAM/OS/hostname/user collection |
| System Network Configuration Discovery | `T1016` | Local/public IP collection |
| File and Directory Discovery | `T1083` | Remote file browsing |
| Input Capture: Keylogging | `T1056.001` | Keylogger control |
| Credentials from Web Browsers | `T1555.003` | Chrome saved password theft |
| Steal Web Session Cookie / Token | `T1539` | Discord authentication token theft |
| Screen Capture | `T1113` | GDI/MSS screen capture |
| Audio Capture | `T1123` | Microphone streaming |
| Video Capture | `T1125` | Webcam streaming |
| Data from Local System | `T1005` | File and credential collection |
| Ingress Tool Transfer | `T1105` | Remote file upload |
| Application Layer Protocol: Web Protocols | `T1071.001` | WebSocket JSON C2 |
| Exfiltration Over C2 Channel | `T1041` | Files, credentials and surveillance data |
| File Deletion | `T1070.004` | Self destruct |
| System Shutdown/Reboot | `T1529` | Remote shutdown/restart |

---

## 10. Detection and Mitigation Recommendations

### 10.1 YARA Detection Rule

The following YARA rule targets extracted or unpacked CrowControl content.

```yara
rule CrowControl_RAT_Unpacked {
    meta:
        description = "Detects unpacked CrowControl RAT and credential stealer artifacts"
        severity = "critical"

    strings:
        $c1 = "CrowControl Agent" ascii wide
        $c2 = "CrowControl remote-control agent" ascii
        $c3 = "ws://manage.gleeze.com:3000" ascii

        $p1 = "svc_helper.vbs" ascii wide
        $p2 = "System Service Watchdog" ascii wide
        $p3 = "--no-admin-check" ascii
        $p4 = "--skip-preset" ascii

        $g1 = "grab_tokens" ascii
        $g2 = "grabbed_tokens" ascii
        $g3 = "ChromeData.db" ascii wide
        $g4 = "dQw4w9WgXcQ:" ascii
        $g5 = "Local Storage\\leveldb" ascii wide

        $k1 = "keylogger_start" ascii
        $k2 = "keylogger_data" ascii

    condition:
        5 of them
}
```

### 10.2 Endpoint Detection

Endpoint monitoring should look for a sequence similar to:

```text
PyInstaller-like EXE
    ->
copy into hidden %LOCALAPPDATA% directory
    ->
create hidden .sys backup
    ->
write svc_helper.vbs
    ->
create Scheduled Task
    ->
write HKCU Run value
    ->
connect to manage.gleeze.com:3000
```

The following process pattern is especially suspicious when launched from a user AppData path:

```text
wscript.exe //B //Nologo <path>\svc_helper.vbs
```

### 10.3 Credential Theft Detection

Chrome theft can be detected by monitoring non-browser processes accessing:

```text
Google\Chrome\User Data\Local State
Google\Chrome\User Data\default\Login Data
```

followed by creation of:

```text
%TEMP%\ChromeData.db
```

Discord token theft can be detected by suspicious access to:

```text
Discord\Local Storage\leveldb
```

or equivalent Chromium LevelDB directories.

### 10.4 Network Detection

Network monitoring should prioritize:

```text
DNS: manage.gleeze.com
TCP: destination port 3000
Protocol: WebSocket
```

If payload inspection is possible, CrowControl-specific JSON strings such as `register_agent`, `grabbed_tokens`,
`keylogger_data`, `webcam_frame`, `mic_chunk`, and `terminal_output` provide stronger signatures.

### fun fact

CrowControl is extremely vibecoded from start to finish, From frontend to actual payload and they have fake "Live Session Feed" for some reason lol:

<img width="344" height="114" alt="image" src="https://github.com/user-attachments/assets/3a1174af-3cdf-4387-8148-5d5e37cfbe49" />
<img width="869" height="110" alt="image" src="https://github.com/user-attachments/assets/f465c371-a30d-4754-88d8-7839e53a0bb8" />

---

-thank you for reading
