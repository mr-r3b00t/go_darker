#Requires -Version 5.1
<#
    View-WindowsIdentifiers.ps1

    Purpose : READ-ONLY privacy audit. Enumerates the unique identifiers that
              Windows and the hardware expose about this machine and user -
              the values that can be used to fingerprint or correlate the
              device. Nothing is changed; this only reports.

    Shows   : Machine identifiers (MachineGuid, Windows Product ID, build GUID,
              SMBIOS UUID, SQM/DiagTrack telemetry client IDs), Windows
              activation / licensing (edition, status, partial + full product
              key, OEM firmware key), user/account identifiers (user SID,
              Advertising ID, and the Microsoft account PUID - the real
              "Passport Unique Identifier"), device registration (Entra/Azure
              AD Device ID and the wlidsvc device-login concept), and hardware
              identifiers (BIOS / baseboard / disk serials, MAC addresses,
              CPU, TPM presence/vendor, and the TPM EKpub - the permanent
              per-TPM Endorsement Key that uniquely fingerprints the device).

              NOTE: the Windows Product ID is a licensing/install ID and is
              NOT the PUID. The PUID is a Microsoft ACCOUNT identifier whose
              native form is hexadecimal (per .NET PassportIdentity.HexPUID);
              on modern Windows it is the signed-in account's CID, read here
              in hex with a derived decimal form.

    Privacy : Output contains SENSITIVE data. By default, sensitive values are
              MASKED so the report is safe to share/screenshot. Use -Reveal to
              print full values (e.g. to back up your own product key).

    Notes   : - Windows PowerShell 5.1 compatible. ASCII-only source.
              - Read-only: makes NO changes to the system.
              - Some values (OEM product key, certain WMI/TPM data) require
                Administrator; without it they show "(needs admin)".

    Explain : Each identifier is explained inline BY DEFAULT (what it is, how
              unique/stable it is, why it matters). Use -Brief for a compact
              list without the explanations.

    Device : -ExtractDeviceId (needs admin) reads the DEVICE account PUID that
             wlidsvc registered under the SYSTEM account (S-1-5-18). It runs a
             one-shot scheduled task as SYSTEM to read SYSTEM's IdentityCRL,
             then removes the task. Read-only w.r.t. the identity store.

    Usage   :
        .\View-WindowsIdentifiers.ps1                 # masked report + explanations
        .\View-WindowsIdentifiers.ps1 -Brief          # compact, no explanations
        .\View-WindowsIdentifiers.ps1 -Reveal         # full values (sensitive!)
        .\View-WindowsIdentifiers.ps1 -ExtractDeviceId -Reveal   # incl. device PUID (admin)
        .\View-WindowsIdentifiers.ps1 -Csv .\ids.csv  # export (respects masking)
        .\View-WindowsIdentifiers.ps1 -Reveal -Csv .\ids.csv
        .\View-WindowsIdentifiers.ps1 -Json .\ids.json

    DISCLAIMER: USE AT YOUR OWN RISK. Provided as-is, no warranty. This tool
    only reports identifiers already present on YOUR machine. Handle the
    output (especially with -Reveal) as confidential.
#>

[CmdletBinding()]
param(
    [switch]$Reveal,
    [switch]$Brief,           # suppress the per-identifier explanations (compact view)
    [switch]$ExtractDeviceId, # admin: read the SYSTEM-hive device account PUID via a SYSTEM task
    [string]$Csv,
    [string]$Json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$Script:IsAdmin = Test-IsAdmin

# ---------------------------------------------------------------------------
# Safe getters
# ---------------------------------------------------------------------------
function Get-RegVal {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $p = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $p.$Name
    } catch { return $null }
}

function Get-Cim {
    param([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter = $null)
    try {
        if ($Filter) { return Get-CimInstance -ClassName $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop }
        return Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop
    } catch { return $null }
}

# StrictMode-safe property read.
function Get-PropSafe {
    param($Obj, [string]$Name)
    if ($null -ne $Obj -and $Obj.PSObject.Properties.Match($Name).Count -gt 0) { return $Obj.$Name }
    return $null
}

# Device registration status via the built-in dsregcmd tool (read-only).
# Returns a hashtable of key -> value parsed from "dsregcmd /status".
function Get-DsRegStatus {
    $result = @{}
    try {
        $out = & dsregcmd.exe /status 2>$null
        foreach ($line in $out) {
            if ("$line" -match '^\s*(\S[^:]*?)\s+:\s+(.+?)\s*$') {
                $k = $Matches[1]; $v = $Matches[2]
                if (-not $result.ContainsKey($k)) { $result[$k] = $v }
            }
        }
    } catch { }
    return $result
}

# TPM Endorsement Key public part (EKpub) - a permanent, globally-unique
# identifier baked into the TPM at manufacture. Needs admin. Uses the built-in
# Get-TpmEndorsementKeyInfo cmdlet; returns the EKpub hash and (if RSA) the
# modulus so the actual public key can be recorded.
# Minimal ASN.1/DER walker: collects every INTEGER value in the blob, descending
# into SEQUENCEs and BIT STRINGs. Used to pull the RSA modulus (the longest
# INTEGER) out of the EKpub without relying on .NET Core-only import APIs.
function Invoke-Asn1Walk {
    param([byte[]]$d, [int]$s, [int]$e, [int]$depth = 0)
    if ($depth -gt 24) { return }
    $i = $s
    while ($i -lt $e) {
        $tag = $d[$i]; $i++
        if ($i -ge $e) { break }
        $b = $d[$i]; $i++
        if ($b -lt 0x80) { $len = $b } else {
            $n = $b -band 0x7f
            if ($n -eq 0 -or ($i + $n) -gt $e) { break }
            $len = 0; for ($k = 0; $k -lt $n; $k++) { $len = ($len * 256) + $d[$i]; $i++ }
        }
        if (($i + $len) -gt $e) { break }
        if ($tag -eq 0x02) { [void]$Script:Asn1Ints.Add([byte[]]($d[$i..($i + $len - 1)])) }
        elseif ($tag -eq 0x03) { if ($len -gt 1) { Invoke-Asn1Walk $d ($i + 1) ($i + $len) ($depth + 1) } }
        elseif (($tag -band 0x20) -ne 0) { Invoke-Asn1Walk $d $i ($i + $len) ($depth + 1) }
        $i += $len
    }
}

function Get-RsaModulus {
    param([byte[]]$Der)
    $Script:Asn1Ints = New-Object System.Collections.ArrayList
    try { Invoke-Asn1Walk -d $Der -s 0 -e $Der.Length } catch { }
    $best = $null
    foreach ($b in $Script:Asn1Ints) { if ($null -eq $best -or $b.Length -gt $best.Length) { $best = $b } }
    if ($null -eq $best -or $best.Length -lt 128) { return $null }   # <1024-bit => not an RSA modulus (e.g. ECC EK)
    if ($best.Length -gt 1 -and $best[0] -eq 0) { $best = $best[1..($best.Length - 1)] }  # strip DER sign byte
    return [byte[]]$best
}

function Get-Sha {
    param([byte[]]$Bytes, [ValidateSet('SHA1','SHA256')][string]$Algo = 'SHA256')
    $h = $null
    try {
        $h = [System.Security.Cryptography.HashAlgorithm]::Create($Algo)
        $hb = $h.ComputeHash($Bytes)
        return (-join ($hb | ForEach-Object { $_.ToString('x2') }))
    } finally { if ($h) { $h.Dispose() } }
}

function Get-TpmEkPub {
    # Windows exposes PublicKey as AsnEncodedData (DER SubjectPublicKeyInfo) and
    # often leaves PublicKeyHash empty - so we base64 the DER (the actual EKpub)
    # and compute the SHA-256 ourselves as a stable fingerprint.
    $info = [pscustomobject]@{ Available = $false; Present = $false; WinHash = $null; Sha256 = $null; Sha1 = $null; ModSha256 = $null; DerB64 = $null }
    if (-not (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue)) { return $info }
    $info.Available = $true
    try {
        $ek = Get-TpmEndorsementKeyInfo -ErrorAction Stop
        $info.Present = [bool](Get-PropSafe $ek 'IsPresent')
        $h = Get-PropSafe $ek 'PublicKeyHash'
        if ($h -and "$h".Trim()) { $info.WinHash = "$h".Trim() }
        $pk  = Get-PropSafe $ek 'PublicKey'      # System.Security.Cryptography.AsnEncodedData
        $raw = if ($pk) { Get-PropSafe $pk 'RawData' } else { $null }
        if ($raw -and $raw.Length -gt 0) {
            $bytes = [byte[]]$raw
            $info.DerB64 = [Convert]::ToBase64String($bytes)
            $info.Sha256 = Get-Sha -Bytes $bytes -Algo SHA256   # hash of the DER SubjectPublicKeyInfo
            $info.Sha1   = Get-Sha -Bytes $bytes -Algo SHA1
            $mod = Get-RsaModulus -Der $bytes                   # raw RSA modulus (null for ECC EKs)
            if ($mod) { $info.ModSha256 = Get-Sha -Bytes $mod -Algo SHA256 }
        }
    } catch { }
    return $info
}

# Microsoft account identity: reads the signed-in account's CID (hex) and
# derives the PUID (decimal). Legacy "Microsoft Passport" backend identifier.
function Get-MsaAccounts {
    $out = New-Object System.Collections.ArrayList
    $base = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties'
    try {
        if (Test-Path -LiteralPath $base) {
            foreach ($sub in (Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
                $props = $null
                try { $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop } catch { }
                $cid   = Get-PropSafe $props 'cid'
                $email = Split-Path $sub.Name -Leaf
                if ($cid) {
                    $puid = $null
                    try { $puid = ([Convert]::ToUInt64($cid, 16)).ToString() } catch { $puid = $null }
                    [void]$out.Add([pscustomobject]@{ Account = $email; Cid = $cid; Puid = $puid })
                }
            }
        }
    } catch { }
    return $out
}

# Extract the DEVICE account PUID. Windows registers the device with Microsoft
# under the SYSTEM account (S-1-5-18), so its IdentityCRL entry is not visible
# from a normal admin's HKCU. With admin we run a one-shot scheduled task as
# SYSTEM that reads SYSTEM's IdentityCRL and returns the device CID/PUID via a
# temp file. Read-only w.r.t. the identity store; the temp task is removed.
function Get-DeviceIdentityAsSystem {
    $results = New-Object System.Collections.ArrayList
    $tmp      = Join-Path $env:TEMP ('wid_dev_{0}.json' -f $PID)
    $ps1      = Join-Path $env:TEMP ('wid_dev_{0}.ps1'  -f $PID)
    $taskName = "WID_DeviceExtract_$PID"
    $payload = @"
`$ErrorActionPreference='SilentlyContinue'
`$found=@{}
`$roots=@('HKCU:\SOFTWARE\Microsoft\IdentityCRL','HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\S-1-5-18')
foreach(`$root in `$roots){
  if(Test-Path `$root){
    `$keys=@(Get-Item `$root -ErrorAction SilentlyContinue) + @(Get-ChildItem `$root -Recurse -ErrorAction SilentlyContinue)
    foreach(`$k in `$keys){
      `$props=Get-ItemProperty -LiteralPath `$k.PSPath -ErrorAction SilentlyContinue
      if(`$props){
        foreach(`$vn in @('cid','CID')){
          if(`$props.PSObject.Properties.Match(`$vn).Count -gt 0){
            `$cid="`$(`$props.`$vn)"
            if(`$cid -and -not `$found.ContainsKey(`$cid)){
              `$puid=`$null; try{`$puid=([Convert]::ToUInt64(`$cid,16)).ToString()}catch{}
              `$found[`$cid]=[pscustomobject]@{Account=(Split-Path `$k.Name -Leaf);Cid=`$cid;Puid=`$puid;KeyPath="`$(`$k.Name)"}
            }
          }
        }
      }
    }
  }
}
@(`$found.Values) | ConvertTo-Json -Depth 4 | Out-File -FilePath '$tmp' -Encoding ASCII
"@
    try {
        Set-Content -LiteralPath $ps1 -Value $payload -Encoding ASCII
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $ps1)
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $tries = 0
        while ($tries -lt 100) {
            Start-Sleep -Milliseconds 200
            $st = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
            if ((Test-Path -LiteralPath $tmp) -and $st -ne 'Running') { break }
            $tries++
        }
        if (Test-Path -LiteralPath $tmp) {
            $json = Get-Content -LiteralPath $tmp -Raw
            if ($json -and $json.Trim()) {
                foreach ($e in @($json | ConvertFrom-Json)) { [void]$results.Add($e) }
            }
        }
    } catch {
        # surfaced by the caller as "(extraction failed)"
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ps1 -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    return $results
}

# ---------------------------------------------------------------------------
# Product key decoder (classic DigitalProductId base-24 decode)
#   Decodes the product key stored in the registry. Legitimate: reads YOUR
#   machine's own installed key so you can record it before a reinstall.
# ---------------------------------------------------------------------------
function ConvertFrom-DigitalProductId {
    param([byte[]]$Id)
    if ($null -eq $Id -or $Id.Count -lt 67) { return $null }
    try {
        $chars   = 'BCDFGHJKMPQRTVWXY2346789'
        $offset  = 52
        $isWin8  = [int](([math]::Floor($Id[66] / 6)) -band 1)
        $Id[66]  = [byte](($Id[66] -band 0xF7) -bor (($isWin8 -band 2) * 4))
        $key = ''
        for ($i = 24; $i -ge 0; $i--) {
            $cur = 0
            for ($j = 14; $j -ge 0; $j--) {
                $cur = ($cur * 256) + [int]$Id[$offset + $j]
                $Id[$offset + $j] = [byte][math]::Floor($cur / 24)
                $cur = $cur % 24
            }
            $key = $chars[$cur] + $key
        }
        if ($isWin8 -eq 1) {
            $last  = $key.Substring(1, 1)
            $key   = $key.Remove(1, 1)
            $insAt = [int]$last
            $key   = $key.Insert($insAt, 'N')
        }
        # group into 5x5
        $groups = @()
        for ($g = 0; $g -lt 25; $g += 5) { $groups += $key.Substring($g, 5) }
        return ($groups -join '-')
    } catch { return $null }
}

# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------
function Format-Masked {
    param($Value, [switch]$Sensitive)
    if ($null -eq $Value -or "$Value" -eq '') { return '(not set)' }
    $s = "$Value"
    # Never mask status placeholders like (needs admin) / (not set) / (unavailable)
    if ($s -match '^\(.*\)$') { return $s }
    if (-not $Sensitive -or $Reveal) { return $s }

    # Product-key style AAAAA-BBBBB-... : keep first and last group
    if ($s -match '^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$') {
        $parts = $s.Split('-')
        return ('{0}-XXXXX-XXXXX-XXXXX-{1}' -f $parts[0], $parts[4])
    }
    # GUID-ish / long strings: show first 6 chars
    $keep = [math]::Min(6, $s.Length)
    return ($s.Substring(0, $keep) + ('*' * [math]::Max(0, ($s.Length - $keep))))
}

# ---------------------------------------------------------------------------
# Identifier collection
# ---------------------------------------------------------------------------
function New-Id {
    param([string]$Category, [string]$Name, $Value, [switch]$Sensitive, [string]$Source = '', [string]$Explain = '')
    [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Raw       = $Value
        Sensitive = [bool]$Sensitive
        Source    = $Source
        Explain   = $Explain
    }
}

function Get-Identifiers {
    $ids = New-Object System.Collections.ArrayList
    $cvNt   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $crypto = 'HKLM:\SOFTWARE\Microsoft\Cryptography'
    $sqm    = 'HKLM:\SOFTWARE\Microsoft\SQMClient'
    $adv    = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'

    $os   = Get-Cim 'Win32_OperatingSystem'
    $cs   = Get-Cim 'Win32_ComputerSystem'
    $csp  = Get-Cim 'Win32_ComputerSystemProduct'
    $bios = Get-Cim 'Win32_BIOS'
    $base = Get-Cim 'Win32_BaseBoard'
    $cpu  = Get-Cim 'Win32_Processor'

    # ---- Machine ----
    [void]$ids.Add( (New-Id 'Machine' 'Computer name' $env:COMPUTERNAME -Source 'env' `
        -Explain 'NetBIOS/host name of this PC; broadcast on local networks and written into many logs.') )
    [void]$ids.Add( (New-Id 'Machine' 'MachineGuid' (Get-RegVal $crypto 'MachineGuid') -Sensitive -Source 'Cryptography\MachineGuid' `
        -Explain 'Random GUID created at OS install. Stable for the life of the install and used by many Microsoft services as a device correlator - often a better cross-service fingerprint than the Product ID.') )
    [void]$ids.Add( (New-Id 'Machine' 'Windows Product ID' (Get-RegVal $cvNt 'ProductId') -Sensitive -Source 'CurrentVersion\ProductId' `
        -Explain '20-digit Windows licensing/installation ID derived from your product key plus install-specific data at setup. Not the key and not reversible to it; changes on reinstall. NOTE: this is the Windows Product ID - it is NOT the PUID. The PUID is a Microsoft ACCOUNT identifier (see User section).') )
    [void]$ids.Add( (New-Id 'Machine' 'Build GUID' (Get-RegVal $cvNt 'BuildGUID') -Source 'CurrentVersion\BuildGUID' `
        -Explain 'Identifies the specific OS build image, not the user. Same across all PCs on the same build.') )
    [void]$ids.Add( (New-Id 'Machine' 'Install date' $(if ($os) { $os.InstallDate } else { $null }) -Source 'Win32_OperatingSystem' `
        -Explain 'When this Windows was installed; helps date/distinguish an install.') )
    if ($csp) {
        [void]$ids.Add( (New-Id 'Machine' 'SMBIOS UUID' $csp.UUID -Sensitive -Source 'Win32_ComputerSystemProduct' `
            -Explain 'System UUID set in firmware. Hardware-bound: survives OS reinstalls, so a strong permanent device fingerprint.') )
        [void]$ids.Add( (New-Id 'Machine' 'System SKU/IdentifyingNumber' $csp.IdentifyingNumber -Sensitive -Source 'Win32_ComputerSystemProduct' `
            -Explain 'OEM system serial/SKU from firmware; identifies the physical unit/model.') )
    }

    # ---- Telemetry client IDs ----
    [void]$ids.Add( (New-Id 'Telemetry' 'SQM Machine ID' (Get-RegVal $sqm 'MachineId') -Sensitive -Source 'SQMClient\MachineId' `
        -Explain 'Client ID tagging this device in the legacy CEIP/SQM ("Software Quality Metrics") telemetry pipeline.') )
    [void]$ids.Add( (New-Id 'Telemetry' 'SQM User ID' (Get-RegVal "$sqm\Windows" 'UserId') -Sensitive -Source 'SQMClient\Windows\UserId' `
        -Explain 'Per-user CEIP/SQM identifier.') )
    # Diagnostics / Universal Telemetry Client ID (if present)
    $utcClientId = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests' 'ClientId'
    [void]$ids.Add( (New-Id 'Telemetry' 'DiagTrack Client ID' $utcClientId -Sensitive -Source 'DiagTrack\SettingsRequests\ClientId' `
        -Explain 'Identifier used by the Connected User Experiences and Telemetry (DiagTrack) service that ships diagnostic data to Microsoft.') )

    # ---- Activation / licensing ----
    if ($os) {
        [void]$ids.Add( (New-Id 'Activation' 'Windows edition' $os.Caption -Source 'Win32_OperatingSystem' `
            -Explain 'The installed Windows edition/SKU.') )
    }
    $partial = $null; $licStatus = $null; $licDesc = $null; $chan = $null
    $lic = Get-Cim 'SoftwareLicensingProduct' -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
    if ($lic) {
        $lic = @($lic)[0]
        $partial = $lic.PartialProductKey
        $chan    = $lic.ProductKeyChannel
        $map = @{ 0='Unlicensed'; 1='Licensed'; 2='OOB Grace'; 3='OOT Grace'; 4='Non-Genuine Grace'; 5='Notification'; 6='Extended Grace' }
        $licStatus = if ($map.ContainsKey([int]$lic.LicenseStatus)) { $map[[int]$lic.LicenseStatus] } else { $lic.LicenseStatus }
        $licDesc = $lic.Description
    }
    [void]$ids.Add( (New-Id 'Activation' 'License status' $licStatus -Source 'SoftwareLicensingProduct' `
        -Explain 'Current activation state (Licensed, grace period, notification, etc.).') )
    [void]$ids.Add( (New-Id 'Activation' 'License channel' $chan -Source 'SoftwareLicensingProduct' `
        -Explain 'How Windows was licensed: Retail, OEM, or Volume (MAK/KMS).') )
    [void]$ids.Add( (New-Id 'Activation' 'License description' $licDesc -Source 'SoftwareLicensingProduct' `
        -Explain 'Human-readable licensing product description.') )
    [void]$ids.Add( (New-Id 'Activation' 'Partial product key' $partial -Sensitive -Source 'SoftwareLicensingProduct' `
        -Explain 'Last 5 characters of the active product key, exactly as Windows itself displays them.') )

    # OEM firmware key (needs admin)
    $oemKey = $null
    if ($Script:IsAdmin) {
        $sls = Get-Cim 'SoftwareLicensingService'
        if ($sls) { $oemKey = $sls.OA3xOriginalProductKey }
        if ([string]::IsNullOrEmpty($oemKey)) { $oemKey = '(none in firmware)' }
    } else {
        $oemKey = '(needs admin)'
    }
    [void]$ids.Add( (New-Id 'Activation' 'OEM firmware key (OA3)' $oemKey -Sensitive -Source 'SoftwareLicensingService.OA3xOriginalProductKey' `
        -Explain 'Full product key the OEM embedded in firmware (BIOS/ACPI MSDM table). Reading it needs admin. Useful to record before a reinstall.') )

    # Decoded installed product key from DigitalProductId
    $decoded = $null
    $dpi = Get-RegVal $cvNt 'DigitalProductId'
    if ($dpi) {
        try { $decoded = ConvertFrom-DigitalProductId -Id ([byte[]]$dpi) } catch { $decoded = $null }
    }
    if ([string]::IsNullOrEmpty($decoded)) {
        $decoded = '(unavailable)'
    } else {
        # Volume (MAK/KMS) channels do not store a recoverable key: decode is garbage
        # (typically a single repeated character). Detect and report honestly.
        $clean    = $decoded -replace '-', ''
        $distinct = @($clean.ToCharArray() | Select-Object -Unique).Count
        if ($distinct -le 3) { $decoded = '(unavailable - volume/MAK license)' }
    }
    [void]$ids.Add( (New-Id 'Activation' 'Installed product key (decoded)' $decoded -Sensitive -Source 'CurrentVersion\DigitalProductId' `
        -Explain 'Full key recovered from the DigitalProductId blob (classic base-24 decode). Retail/OEM installs decode to a real key; volume (MAK/KMS) installs do not store a recoverable key.') )

    # Consolidated "full product key": pick the best available source, or say why none exists.
    $keyPattern = '^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$'
    $fullKey = $null; $fullSrc = $null
    if ($oemKey  -and "$oemKey"  -match $keyPattern) { $fullKey = "$oemKey";  $fullSrc = 'OEM firmware (OA3xOriginalProductKey)' }
    elseif ($decoded -and "$decoded" -match $keyPattern) { $fullKey = "$decoded"; $fullSrc = 'DigitalProductId decode' }
    if ($fullKey) {
        [void]$ids.Add( (New-Id 'Activation' 'Full product key' $fullKey -Sensitive -Source $fullSrc `
            -Explain ('The full 25-character product key for this install, recovered from ' + $fullSrc + '. Masked unless -Reveal.')) )
    } else {
        $reason =
            if ("$chan" -match 'Volume|MAK|KMS') { '(not recoverable - Volume/MAK/KMS: only the last 5 chars are stored on the device)' }
            elseif (-not $Script:IsAdmin)        { '(not recoverable unelevated - run as admin with -Reveal; may exist in OEM firmware)' }
            else                                 { '(not recoverable on this install)' }
        [void]$ids.Add( (New-Id 'Activation' 'Full product key' $reason -Source 'best-effort' `
            -Explain 'The complete 25-character key. It is only recoverable for retail/OEM installs (via OEM firmware OA3 key or DigitalProductId decode). Volume MAK/KMS keys are NOT stored on the device by design - Windows keeps only the last 5 characters - so no tool can display them.') )
    }

    # ---- Advertising / user ----
    [void]$ids.Add( (New-Id 'User' 'User name' ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) -Source 'env' `
        -Explain 'Domain (or machine) and username of the current account.') )
    try {
        $sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        [void]$ids.Add( (New-Id 'User' 'User SID' $sid -Sensitive -Source 'WindowsIdentity' `
            -Explain 'Security Identifier that uniquely identifies this account on the machine/domain. Embedded in ACLs and many logs.') )
    } catch { }
    $advId = Get-RegVal $adv 'Id'
    [void]$ids.Add( (New-Id 'User' 'Advertising ID' $advId -Sensitive -Source 'AdvertisingInfo\Id' `
        -Explain 'Per-user identifier apps use to correlate you for ad targeting across apps.') )
    $advOn = Get-RegVal $adv 'Enabled'
    [void]$ids.Add( (New-Id 'User' 'Advertising ID enabled' $advOn -Source 'AdvertisingInfo\Enabled' `
        -Explain 'Whether the Advertising ID is active (1) or turned off (0).') )

    # Microsoft account PUID (the "Passport Unique Identifier").
    # The PUID's native representation is HEXADECIMAL - the .NET Passport API
    # exposed it as PassportIdentity.HexPUID (a hex string). On modern Windows
    # that hex value is the signed-in account's CID; decimal is derived from it.
    $msa = @(Get-MsaAccounts)
    if ($msa.Count -eq 0) {
        [void]$ids.Add( (New-Id 'User' 'Microsoft account PUID' '(no Microsoft account signed in)' -Source 'IdentityCRL' `
            -Explain 'PUID (Passport Unique Identifier): a permanent ID Microsoft assigns your ACCOUNT in its backend identity system (legacy "Microsoft Passport", later Windows Live ID, now Microsoft account). Natively hexadecimal (see .NET PassportIdentity.HexPUID). None found here - this appears to be a local account.') )
    } else {
        foreach ($a in $msa) {
            [void]$ids.Add( (New-Id 'User' 'Microsoft account email' $a.Account -Sensitive -Source 'IdentityCRL\UserExtendedProperties' `
                -Explain 'Email of a Microsoft account signed in on this machine.') )
            [void]$ids.Add( (New-Id 'User' 'MS account PUID (hex / CID)' $a.Cid -Sensitive -Source 'IdentityCRL\...\cid' `
                -Explain 'PUID in HEX - its native form (the value the Passport API returned as HexPUID). On modern Windows this is the account CID, also seen in OneDrive URLs and auth tokens.') )
            [void]$ids.Add( (New-Id 'User' 'MS account PUID (decimal)' $a.Puid -Sensitive -Source 'derived: ToUInt64(HexPUID,16)' `
                -Explain 'The same PUID converted to decimal (~18 digits). Passport Unique Identifier: a permanent Microsoft ACCOUNT ID from the legacy "Microsoft Passport" system (later Windows Live ID), identifying the account across Microsoft services regardless of device.') )
        }
    }

    # ---- Device (registration with Microsoft, distinct from the user) ----
    # On first internet connection wlidsvc (Windows Live ID) registers THIS
    # DEVICE with Microsoft using hardware identity (disk, SMBIOS, TPM) and
    # receives a device PUID/GDID + device token. The consumer device token is
    # DPAPI-protected (not a plain value); the documented device ID that IS
    # readable is the Entra/Azure AD Device ID via dsregcmd.
    $ds = Get-DsRegStatus
    $devId = if ($ds.ContainsKey('DeviceId')) { $ds['DeviceId'] } else { $null }
    if ([string]::IsNullOrWhiteSpace($devId)) { $devId = '(device not registered with Entra/Azure AD)' }
    [void]$ids.Add( (New-Id 'Device' 'Entra/Azure AD Device ID' $devId -Sensitive -Source 'dsregcmd /status' `
        -Explain 'GUID identifying this device to Microsoft Entra ID (Azure AD) when the device is registered/joined. This is the readable device identity; the consumer MSA device token issued by wlidsvc is DPAPI-protected and not shown.') )
    foreach ($jk in @('AzureAdJoined','EnterpriseJoined','DomainJoined','WorkplaceJoined')) {
        if ($ds.ContainsKey($jk)) {
            [void]$ids.Add( (New-Id 'Device' $jk $ds[$jk] -Source 'dsregcmd /status' `
                -Explain 'Device join/registration state reported by dsregcmd.') )
        }
    }
    if ($ds.ContainsKey('TenantId')) {
        [void]$ids.Add( (New-Id 'Device' 'Entra Tenant ID' $ds['TenantId'] -Sensitive -Source 'dsregcmd /status' `
            -Explain 'Identifier of the Entra ID (Azure AD) tenant this device is registered to, if any.') )
    }
    $wlid = if ($msa.Count -gt 0) { 'MSA present - device registered with Microsoft' } else { 'no Microsoft account signed in' }
    [void]$ids.Add( (New-Id 'Device' 'MSA device registration' $wlid -Source 'wlidsvc (concept)' `
        -Explain 'On first internet connection the Windows Live ID service (wlidsvc) logs this DEVICE in to Microsoft using hardware identifiers (disk serial, SMBIOS UUID, TPM) and receives a device PUID/GDID and a device token. Pass -ExtractDeviceId (admin) to read the device account PUID from the SYSTEM hive; the device token itself is DPAPI-protected and not surfaced.') )

    # Device account PUID - registered under SYSTEM (S-1-5-18), read via -ExtractDeviceId
    if ($ExtractDeviceId) {
        if (-not $Script:IsAdmin) {
            [void]$ids.Add( (New-Id 'Device' 'Device account PUID' '(needs admin)' -Source 'IdentityCRL as SYSTEM' `
                -Explain 'The device MSA PUID lives in the SYSTEM account hive; extracting it needs Administrator (the tool runs a one-shot SYSTEM task).') )
        } else {
            $dev = @(Get-DeviceIdentityAsSystem)
            if ($dev.Count -eq 0) {
                [void]$ids.Add( (New-Id 'Device' 'Device account PUID' '(none found - no device registration)' -Source 'IdentityCRL as SYSTEM' `
                    -Explain 'No device account was found in the SYSTEM IdentityCRL store (device may never have registered with an MSA).') )
            } else {
                foreach ($d in $dev) {
                    [void]$ids.Add( (New-Id 'Device' 'Device account' (Get-PropSafe $d 'Account') -Sensitive -Source 'SYSTEM HKCU IdentityCRL\UserExtendedProperties' `
                        -Explain 'The hidden device MSA account name Windows created to log this device in to Microsoft.') )
                    [void]$ids.Add( (New-Id 'Device' 'Device PUID (hex / CID)' (Get-PropSafe $d 'Cid') -Sensitive -Source 'SYSTEM IdentityCRL\...\cid' `
                        -Explain 'The device account CID in hex - the device PUID/GDID Microsoft issued when this device registered using its hardware identity. Native (hex) form.') )
                    [void]$ids.Add( (New-Id 'Device' 'Device PUID (decimal)' (Get-PropSafe $d 'Puid') -Sensitive -Source 'derived: ToUInt64(CID,16)' `
                        -Explain 'The device PUID converted to decimal (~18 digits).') )
                }
            }
        }
    }

    # ---- Hardware ----
    if ($bios) {
        [void]$ids.Add( (New-Id 'Hardware' 'BIOS serial number' $bios.SerialNumber -Sensitive -Source 'Win32_BIOS' `
            -Explain 'System serial from firmware; hardware-bound and survives OS reinstall - a strong permanent fingerprint.') )
    }
    if ($base) {
        [void]$ids.Add( (New-Id 'Hardware' 'Baseboard serial' $base.SerialNumber -Sensitive -Source 'Win32_BaseBoard' `
            -Explain 'Motherboard serial number.') )
    }
    if ($cpu) {
        $cpu1 = @($cpu)[0]
        [void]$ids.Add( (New-Id 'Hardware' 'CPU ProcessorId' $cpu1.ProcessorId -Sensitive -Source 'Win32_Processor' `
            -Explain 'Processor signature/feature ID. Not globally unique, but adds entropy to a hardware fingerprint.') )
    }
    # Disk serials
    $disks = Get-Cim 'Win32_DiskDrive'
    if ($disks) {
        $n = 0
        foreach ($d in @($disks)) {
            $n++
            $ser = if ($d.SerialNumber) { ($d.SerialNumber).Trim() } else { '(none)' }
            [void]$ids.Add( (New-Id 'Hardware' ("Disk {0} serial" -f $n) $ser -Sensitive -Source 'Win32_DiskDrive' `
                -Explain 'Physical drive serial number; a strong, portable hardware fingerprint.') )
        }
    }
    # MAC addresses (physical adapters with a MAC)
    $nics = Get-Cim 'Win32_NetworkAdapter' -Filter 'PhysicalAdapter=TRUE AND MACAddress IS NOT NULL'
    if ($nics) {
        foreach ($nic in @($nics)) {
            [void]$ids.Add( (New-Id 'Network' ("MAC - {0}" -f $nic.NetConnectionID) $nic.MACAddress -Sensitive -Source 'Win32_NetworkAdapter' `
                -Explain 'Hardware address of this network adapter; identifies the device on every network it joins (unless MAC randomization is on).') )
        }
    }
    # TPM (needs admin; separate namespace)
    $tpm = Get-Cim 'Win32_Tpm' -Namespace 'root\cimv2\Security\MicrosoftTpm'
    if ($tpm) {
        $tpm1 = @($tpm)[0]
        [void]$ids.Add( (New-Id 'Hardware' 'TPM present' $tpm1.IsEnabled_InitialValue -Source 'Win32_Tpm' `
            -Explain 'Whether a Trusted Platform Module is enabled; underpins device attestation and disk encryption keys.') )
        [void]$ids.Add( (New-Id 'Hardware' 'TPM manufacturer ID' $tpm1.ManufacturerId -Source 'Win32_Tpm' `
            -Explain 'Vendor ID of the TPM chip.') )
    } elseif (-not $Script:IsAdmin) {
        [void]$ids.Add( (New-Id 'Hardware' 'TPM info' '(needs admin)' -Source 'Win32_Tpm' `
            -Explain 'TPM chip details (presence, vendor); requires Administrator to read.') )
    }

    # TPM Endorsement Key public part (EKpub) - the strongest permanent ID
    $ekExplain = 'TPM Endorsement Key (public part). A permanent, globally-unique key burned into the TPM at manufacture - it cannot be changed, reset or removed. Windows/Microsoft device attestation and registration use the EKpub (or its hash) to uniquely identify THIS exact TPM, and therefore this device, for its entire lifetime. The strongest hardware fingerprint on the machine.'
    if (-not (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue)) {
        [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub' '(TPM cmdlets unavailable)' -Source 'Get-TpmEndorsementKeyInfo' -Explain $ekExplain) )
    } elseif (-not $Script:IsAdmin) {
        [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub' '(needs admin)' -Source 'Get-TpmEndorsementKeyInfo' -Explain $ekExplain) )
    } else {
        $ek = Get-TpmEkPub
        if ($ek.DerB64 -or $ek.WinHash -or $ek.Sha256) {
            if ($ek.WinHash) {
                [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub hash (Windows)' $ek.WinHash -Sensitive -Source 'Get-TpmEndorsementKeyInfo.PublicKeyHash' -Explain $ekExplain) )
            }
            if ($ek.Sha256) {
                [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub SHA-256 (SPKI)' $ek.Sha256 -Sensitive -Source 'SHA-256 of PublicKey.RawData (DER SPKI)' `
                    -Explain ($ekExplain + ' (SHA-256 over the DER SubjectPublicKeyInfo; computed here since Windows left PublicKeyHash empty.)')) )
            }
            if ($ek.Sha1) {
                [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub SHA-1 (SPKI)' $ek.Sha1 -Sensitive -Source 'SHA-1 of PublicKey.RawData (DER SPKI)' `
                    -Explain 'SHA-1 fingerprint of the EKpub DER SubjectPublicKeyInfo. Some tools/attestation flows key off SHA-1 rather than SHA-256.') )
            }
            if ($ek.ModSha256) {
                [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub modulus SHA-256' $ek.ModSha256 -Sensitive -Source 'SHA-256 of raw RSA modulus' `
                    -Explain 'SHA-256 over the RAW RSA modulus (public key value only, DER wrapper stripped) - the "raw-modulus" fingerprint some Microsoft/attestation formats use, as opposed to hashing the whole SubjectPublicKeyInfo.') )
            }
            if ($ek.DerB64) {
                [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub (DER, b64)' $ek.DerB64 -Sensitive -Source 'Get-TpmEndorsementKeyInfo.PublicKey.RawData' `
                    -Explain 'The actual EKpub public key: the DER-encoded SubjectPublicKeyInfo, base64. This IS the endorsement public key (not just a hash) - from it you can derive any required format. Use -Reveal to record it.') )
                [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub Name (TPM2B_NAME)' '(not derivable from this cmdlet)' -Source 'n/a' `
                    -Explain 'The TPM "Name" (TPM2B_NAME = alg id + hash of the TPMT_PUBLIC area) is NOT computable from the DER SubjectPublicKeyInfo this cmdlet returns - it needs the raw TPMT_PUBLIC blob (via tpm2-tools or the NCrypt/PCPKSP provider). Shown for completeness; the values above are what is available here.') )
            }
        } elseif ($ek.Present) {
            [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub' '(EK present but public key not readable)' -Source 'Get-TpmEndorsementKeyInfo' -Explain $ekExplain) )
        } else {
            [void]$ids.Add( (New-Id 'Hardware' 'TPM EKpub' '(no EK present / not readable)' -Source 'Get-TpmEndorsementKeyInfo' -Explain $ekExplain) )
        }
    }

    return $ids
}

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------
function Show-Report {
    param($Ids)

    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor Cyan
    Write-Host '  Windows Identifier Privacy Audit (READ-ONLY)' -ForegroundColor Cyan
    Write-Host ('  Host: {0}   Admin: {1}   {2}' -f $env:COMPUTERNAME, $Script:IsAdmin, (Get-Date)) -ForegroundColor DarkCyan
    if ($Reveal) {
        Write-Host '  MODE: REVEAL - full sensitive values shown. Handle as confidential.' -ForegroundColor Red
    } else {
        Write-Host '  MODE: MASKED - sensitive values redacted. Use -Reveal for full values.' -ForegroundColor Magenta
    }
    Write-Host '==================================================================' -ForegroundColor Cyan

    $categories = @('Machine','Activation','Telemetry','User','Device','Hardware','Network')
    foreach ($cat in $categories) {
        $group = @($Ids | Where-Object { $_.Category -eq $cat })
        if ($group.Count -eq 0) { continue }
        Write-Host ''
        Write-Host ("  [{0}]" -f $cat) -ForegroundColor White
        foreach ($id in $group) {
            $disp  = Format-Masked -Value $id.Raw -Sensitive:$id.Sensitive
            $color = if ($id.Sensitive) { 'Yellow' } else { 'Gray' }
            $tag   = if ($id.Sensitive) { '!' } else { ' ' }
            Write-Host ('  {0} {1,-32}' -f $tag, $id.Name) -NoNewline
            Write-Host $disp -ForegroundColor $color
            if (-not $Brief -and $id.Explain) {
                Write-Host ('      {0}' -f $id.Explain) -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ''
    Write-Host '  ! = sensitive identifier (masked unless -Reveal).' -ForegroundColor DarkYellow
    if ($Brief) {
        Write-Host '  (explanations hidden by -Brief; omit it to show them.)' -ForegroundColor DarkGray
    }
    if (-not $Script:IsAdmin) {
        Write-Host '  Some values need Administrator (OEM key, TPM) - shown as (needs admin).' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

function Export-Rows {
    param($Ids)
    foreach ($id in $Ids) {
        [pscustomobject]@{
            Category    = $id.Category
            Name        = $id.Name
            Value       = (Format-Masked -Value $id.Raw -Sensitive:$id.Sensitive)
            Sensitive   = $id.Sensitive
            Source      = $id.Source
            Explanation = $id.Explain
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ids = Get-Identifiers

Show-Report -Ids $ids

if ($Csv) {
    Export-Rows -Ids $ids | Export-Csv -Path $Csv -NoTypeInformation -Encoding ASCII
    Write-Host ("CSV written to {0}{1}" -f $Csv, $(if (-not $Reveal) { ' (masked)' } else { ' (REVEALED - confidential)' })) -ForegroundColor Green
}
if ($Json) {
    Export-Rows -Ids $ids | ConvertTo-Json -Depth 3 | Out-File -FilePath $Json -Encoding ASCII
    Write-Host ("JSON written to {0}{1}" -f $Json, $(if (-not $Reveal) { ' (masked)' } else { ' (REVEALED - confidential)' })) -ForegroundColor Green
}
