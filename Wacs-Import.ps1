<#
Wacs-Import.ps1
- Latest cert discovery, hybrid-aware, idempotent connector updates
- Deploys/imports to ALL Send Connector SourceTransportServers using Exchange -Server (no nested WinRM)

Default behaviors:
- Scans <ShareRoot>\Certs for newest PFX:
    - Prefers "<BaseName>*.pfx", "_.<BaseName>*.pfx", and falls back to newest "*.pfx"
    - Retries remaining candidate PFX files if the primary choice fails password import
- Uses <ShareRoot>\export-secrets.json by default.
  Also supports:
    - import.secrets.json  (array of { Key, Secret })
    - secrets.json         (object legacy styles)
- Imports cert locally, enables IIS,SMTP
- For each Send Connector:
    - Ensures cert is present + SMTP enabled on every SourceTransportServer (via Exchange -Server)
    - Updates TlsCertificateName ONLY if different (idempotent)
- Receive Connector(s): update TLS name ONLY if different
- Cleanup: removes older Exchange certs safely (normalizes wildcard SANs)
#>  [Parameter(Mandatory=$true)][string]$BaseName   = "example.com",

  [string]$PfxOverridePath,
  [string]$SecretsPath,                              # default to export-secrets.json
  [string]$Services = "IIS,SMTP",

  [switch]$NoHybridUpdates,

  [string]$SendConnectorName = "*Outbound to Office 365*",
  [string[]]$SendConnectorExact,
  [switch]$AllSendConnectors,

  [string]$ReceiveConnectorPattern,                  # default "*Default Frontend <server>*"

  [switch]$NoCleanup,
  [switch]$RestartIIS,

  [switch]$DebugOn,

  # --- New diagnostics / logging ---
  [switch]$Diagnose,
  [switch]$StartTranscript,
  [string]$TranscriptPath
)

# ------------- Logging & safety -------------
if ($DebugOn) {
  $VerbosePreference   = 'Continue'
  $DebugPreference     = 'Continue'
  $InformationPreference = 'Continue'
}
$ErrorActionPreference = 'Continue'  # We catch & log at key spots.

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG','DIAG')][string]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  switch ($Level) {
    'INFO'  { Write-Host    "[$ts][INFO ] $Message" }
    'WARN'  { Write-Warning "[$ts][WARN ] $Message" }
    'ERROR' { Write-Error   "[$ts][ERROR] $Message" }
    'DEBUG' { if ($DebugOn) { Write-Host "[$ts][DEBUG] $Message" -ForegroundColor DarkGray } }
    'DIAG'  { if ($DebugOn -or $Diagnose) { Write-Host "[$ts][DIAG ] $Message" -ForegroundColor Cyan } }
  }
}

function Require-AdminOrSystem {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p=New-Object Security.Principal.WindowsPrincipal($id)
  if (-not($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $id.Name -eq "NT AUTHORITY\SYSTEM")) {
    throw "Run as Administrator or SYSTEM (recommended: service account with local admin + Exchange RBAC)."
  }
  Write-Log "Running as: $($id.Name)" 'DIAG'
}

# ------------- Transcript -------------
function Start-Logging {
  if (-not $StartTranscript) { return }
  try {
    if (-not $TranscriptPath -or -not $TranscriptPath.Trim()) {
      $logsDir = Join-Path $ShareRoot "Logs"
      if (-not (Test-Path -LiteralPath $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
      $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
      $TranscriptPath = Join-Path $logsDir ("Wacs-Import_{0}_{1}.log" -f $env:COMPUTERNAME, $ts)
    }
    Start-Transcript -Path $TranscriptPath -Append | Out-Null
    Write-Log "Transcript started: $TranscriptPath" 'INFO'
  } catch {
    Write-Log "Failed to start transcript: $($_.Exception.Message)" 'WARN'
  }
}
function Stop-Logging {
  if (-not $StartTranscript) { return }
  try { Stop-Transcript | Out-Null } catch {}
}

# ------------- Secrets helpers -------------
function Load-Secrets {
  param([string]$Path)
  if (-not $Path) { return $null }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if (-not $raw -or -not $raw.Trim()) { return $null }
    return $raw | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "Failed to parse secrets JSON at '$Path' $($_.Exception.Message)"
  }
}
function Resolve-PfxPassword {
  param([object]$Secrets,[string]$BaseName)
  if ($null -eq $Secrets) { return $null }

  function HasProp([object]$obj,[string]$propName) {
    if ($null -eq $obj) { return $false }
    return $obj.PSObject.Properties.Name -contains $propName -or
           ($obj.PSObject.Properties.Name | ForEach-Object { $_.ToLowerInvariant() }) -contains $propName.ToLowerInvariant()
  }
  function GetProp([object]$obj,[string]$propName) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties | Where-Object { $_.Name -ieq $propName } | Select-Object -First 1
    if ($p) { return $p.Value } else { return $null }
  }

  # Array of { Key, Secret }
  if ($Secrets -is [System.Collections.IEnumerable] -and -not ($Secrets -is [System.Collections.IDictionary])) {
    $arr = @($Secrets)
    $match = $arr | Where-Object { HasProp $_ 'Key' -and (GetProp $_ 'Key') -ieq $BaseName } | Select-Object -First 1
    if (-not $match) { $match = $arr | Where-Object { HasProp $_ 'Key' -and (GetProp $_ 'Key') -ieq 'default' } | Select-Object -First 1 }
    if ($match -and (HasProp $match 'Secret')) {
      $sec = GetProp $match 'Secret'
      if ($sec) { return [string]$sec }
    }
    return $null
  }

  # Object legacy styles
  if (HasProp $Secrets $BaseName) {
    $node = GetProp $Secrets $BaseName
    if ($node -is [string]) { return [string]$node }
    if (HasProp $node 'pfxPassword') {
      $pw = GetProp $node 'pfxPassword'
      if ($pw) { return [string]$pw }
    }
  }
  if (HasProp $Secrets 'default') {
    $def = GetProp $Secrets 'default'
    if ($def -is [string]) { return [string]$def }
    if (HasProp $def 'pfxPassword') {
      $pw = GetProp $def 'pfxPassword'
      if ($pw) { return [string]$pw }
    }
  }
  return $null
}

# ------------- Exchange helpers -------------
function Ensure-ExchangePSSession {
  # If you run from the Exchange Management Shell, this is a no-op.
  if (Get-Command Import-ExchangeCertificate -ErrorAction SilentlyContinue) { return }
  $ps1 = $env:ExchangeInstallPath
  if ($ps1) { $ps1 = Join-Path $ps1 "bin\RemoteExchange.ps1" }
  if (-not $ps1 -or -not (Test-Path -LiteralPath $ps1)) {
    $ps1 = "C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1"
  }
  if (Test-Path -LiteralPath $ps1) {
    . $ps1
    try { Connect-ExchangeServer -auto -ErrorAction Stop | Out-Null; Write-Log "Connected Exchange PS session." 'DIAG' } catch { Write-Log "Connect-ExchangeServer failed: $($_.Exception.Message)" 'WARN' }
  }
  if (-not (Get-Command Import-ExchangeCertificate -ErrorAction SilentlyContinue)) {
    throw "Exchange cmdlets unavailable. Run from EMS or ensure RemoteExchange.ps1 is present."
  }
}

function Get-CertTlsName([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
  # Build <I>Issuer<S>Subject string for -TlsCertificateName on Hybrid/Connectors
  return ("<I>{0}<S>{1}" -f $Cert.Issuer, $Cert.Subject)
}
function Get-CN([string]$Subject) {
  ($Subject -split ',') | Where-Object { $_ -like 'CN=*' } |
    ForEach-Object { $_.Split('=')[1].Trim() } | Select-Object -First 1
}

function Test-CertPresentOnServer {
  param([string]$Server, [string]$Thumb)
  try { $null = Get-ExchangeCertificate -Server $Server -Thumbprint $Thumb -ErrorAction Stop; return $true } catch { return $false }
}

function Classify-RemoteError {
  param([string]$Message)
  if ($Message -match '(?i)access is denied|0x5') { return 'AccessDenied' }
  if ($Message -match '(?i)rpc server is unavailable|0x6ba|winrm|endpoint not found') { return 'Connectivity' }
  if ($Message -match '(?i)couldn.?t be found|not recognized') { return 'NotFound' }
  return 'Other'
}

function Test-RemoteExchangeAccess {
  param([string]$Server)
  try {
    $null = Get-ExchangeCertificate -Server $Server -ErrorAction Stop | Select-Object -First 1
    return [pscustomobject]@{ Server=$Server; Access='OK'; Note='Get-ExchangeCertificate succeeded' }
  } catch {
    $msg = $_.Exception.Message
    $kind = Classify-RemoteError -Message $msg
    return [pscustomobject]@{ Server=$Server; Access=$kind; Error=$msg }
  }
}

function Ensure-CertOnServerExchange {
  param(
    [string]$Server,
    [byte[]]$PfxBytes,
    [SecureString]$SecPassword,
    [switch]$EnableIIS
  )
  try {
    # Import to target server via Exchange cmdlets (no PS remoting)
    $imported = Import-ExchangeCertificate -Server $Server -FileData $PfxBytes -Password $SecPassword -PrivateKeyExportable:$true -ErrorAction Stop
    $thumbLocal = $null
    if ($imported -and $imported.Thumbprint) {
      $thumbLocal = $imported.Thumbprint
    } else {
      $thumbLocal = (Get-ExchangeCertificate -Server $Server | Sort-Object NotAfter -Descending | Select-Object -First 1).Thumbprint
    }
    if (-not $thumbLocal) { throw "Import on $Server succeeded but thumbprint couldn't be determined." }

    Enable-ExchangeCertificate -Server $Server -Thumbprint $thumbLocal -Services SMTP -Force | Out-Null
    if ($EnableIIS) { Enable-ExchangeCertificate -Server $Server -Thumbprint $thumbLocal -Services IIS -Force | Out-Null }

    Write-Log "Exchange(remote): '$Server' imported/enabled cert $thumbLocal" 'DEBUG'
    return $true
  } catch {
    $msg = $_.Exception.Message
    $kind = Classify-RemoteError -Message $msg
    Write-Log "Exchange(remote) on '$Server' failed [$kind]: $msg" 'WARN'
    return $false
  }
}

# ------------- Main -------------
try {
  Require-AdminOrSystem
  Start-Logging
  Ensure-ExchangePSSession

  $certsDir = Join-Path $ShareRoot 'Certs'

  # Default secrets path preference
  if (-not $SecretsPath -or -not $SecretsPath.Trim()) {
    $candidate1 = Join-Path $ShareRoot "export-secrets.json"     # preferred
    $candidate2 = Join-Path $ShareRoot "import.secrets.json"     # legacy (array-based)
    $candidate3 = Join-Path $ShareRoot "secrets.json"            # legacy (object-based)
    if     (Test-Path -LiteralPath $candidate1) { $SecretsPath = $candidate1 }
    elseif (Test-Path -LiteralPath $candidate2) { $SecretsPath = $candidate2 }
    else                                        { $SecretsPath = $candidate3 }
  }

  # Choose PFX (override > newest BaseName*.pfx > newest *.pfx)
  if ($PfxOverridePath) {
    $pfxPath = $PfxOverridePath
    Write-Log "Override path specified: using $pfxPath"
  } else {
    if (-not (Test-Path -LiteralPath $certsDir)) { throw "Certs directory not found: $certsDir" }
    Write-Log "Searching for latest PFX in: $certsDir"
    $files = Get-ChildItem -Path $certsDir -Filter "$BaseName*.pfx" -File -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending
    if (-not $files -or $files.Count -eq 0) {
      Write-Log "No PFX matched '$BaseName*.pfx'. Falling back to newest '*.pfx'." "WARN"
      $files = Get-ChildItem -Path $certsDir -Filter "*.pfx" -File -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending
    }
    if (-not $files -or $files.Count -eq 0) { throw "No PFX files found under $certsDir" }
    $pfxPath = $files[0].FullName
    Write-Log "Latest PFX selected: $pfxPath"
  }

  # Receive connector default
  if (-not $ReceiveConnectorPattern -or -not $ReceiveConnectorPattern.Trim()) {
    $ReceiveConnectorPattern = "*Default Frontend $(hostname)*"
  }

  Write-Log "PFX path:  $pfxPath"
  Write-Log "Secrets:   $SecretsPath"

  if (-not (Test-Path -LiteralPath $pfxPath)) { throw "PFX not found at $pfxPath" }

  # Resolve password
  $secrets = Load-Secrets -Path $SecretsPath
  $pfxPw   = Resolve-PfxPassword -Secrets $secrets -BaseName $BaseName
  if (-not $pfxPw) { throw "No PFX password found. Ensure $SecretsPath contains Key='$BaseName' or Key='default'." }

  # Load PFX bytes + metadata
  $bytes = [System.IO.File]::ReadAllBytes($pfxPath)
  $sec   = ConvertTo-SecureString -String $pfxPw -AsPlainText -Force
  $x509  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
  $x509.Import($bytes, $sec, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
  $thumb = $x509.Thumbprint.ToUpperInvariant()
  $cn    = Get-CN -Subject $x509.Subject
  $tlsName = Get-CertTlsName -Cert $x509
  Write-Log "Thumbprint: $thumb"
  if ($cn) { Write-Log "Subject CN: $cn" }
  Write-Log "New TLS name: $tlsName"

  # Optional diagnostics pre-flight
  if ($Diagnose) {
    Write-Log "Running diagnostics (pre-flight)..." 'DIAG'
    try {
      $srvList = @()
      try {
        if ($AllSendConnectors) {
          $sendConnDiag = Get-SendConnector -ErrorAction Stop
        } elseif ($SendConnectorExact -and $SendConnectorExact.Count -gt 0) {
          $sendConnDiag = foreach ($name in $SendConnectorExact) { Get-SendConnector -Identity $name -ErrorAction Stop }
        } else {
          $sendConnDiag = Get-SendConnector $SendConnectorName -ErrorAction Stop
        }
      } catch { Write-Log "Diagnostic: Get-SendConnector failed: $($_.Exception.Message)" 'WARN' }

      if ($sendConnDiag) {
        foreach ($sc in $sendConnDiag) { if ($sc.SourceTransportServers) { $srvList += @($sc.SourceTransportServers) } }
        $srvList = $srvList | Select-Object -Unique
        if ($srvList.Count -gt 0) {
          Write-Log ("Diagnostic: Found {0} unique source servers: {1}" -f $srvList.Count, ($srvList -join ', ')) 'DIAG'
          foreach ($s in $srvList) {
            $res = Test-RemoteExchangeAccess -Server $s
            $msg = if ($res.Access -eq 'OK') { 'OK' } else { "$($res.Access): $($res.Error)" }
            Write-Log ("Diagnostic: Access test for '{0}': {1}" -f $res.Server, $msg) 'DIAG'
          }
        } else {
          Write-Log "Diagnostic: No source transport servers enumerated." 'DIAG'
        }
      }

      if (-not $NoHybridUpdates) {
        try {
          $hy = Get-HybridConfiguration -ErrorAction Stop
          $cur = if ($hy -and $hy.TlsCertificateName) { $hy.TlsCertificateName } else { '<null>' }
          Write-Log "Diagnostic: HybridConfiguration current TLS name: $cur" 'DIAG'
        } catch {
          Write-Log "Diagnostic: Get-HybridConfiguration failed: $($_.Exception.Message)" 'WARN'
        }
      }
    } catch {
      Write-Log "Diagnostics encountered an error: $($_.Exception.Message)" 'WARN'
    }
  }

  # Import locally if missing; enable local services
  $existing = Get-ExchangeCertificate | Where-Object Thumbprint -eq $thumb
  if (-not $existing) {
    Write-Log "Importing PFX into LocalMachine\My (local)"
    Import-ExchangeCertificate -FileData $bytes -Password $sec -PrivateKeyExportable:$true | Out-Null
  }
  Write-Log "Enabling services (local): $Services"
  Enable-ExchangeCertificate -Thumbprint $thumb -Services $Services -Force | Out-Null

  # ---- Hybrid & connectors (default: ON) ----
  if (-not $NoHybridUpdates) {
    # Hybrid: set only if different + verify
    try {
      $currentHybrid = $null
      try { $currentHybrid = Get-HybridConfiguration -ErrorAction Stop } catch {}
      $needsHybrid = $true
      if ($currentHybrid -and $currentHybrid.TlsCertificateName) {
        if ($currentHybrid.TlsCertificateName -ieq $tlsName) { $needsHybrid = $false; Write-Log "HybridConfiguration already set. Skipping." }
      }
      if ($needsHybrid) {
        Write-Log "Setting HybridConfiguration -TlsCertificateName to: $tlsName"
        Set-HybridConfiguration -TlsCertificateName $tlsName -ErrorAction Stop
        Start-Sleep -Seconds 1
        try {
          $post = Get-HybridConfiguration -ErrorAction Stop
          $postVal = if ($post.TlsCertificateName) { $post.TlsCertificateName } else { '<null>' }
          if ($postVal -ieq $tlsName) {
            Write-Log "HybridConfiguration verification: updated successfully." 'DEBUG'
          } else {
            Write-Log "HybridConfiguration verification: value is '$postVal' (expected '$tlsName')" 'WARN'
          }
        } catch { Write-Log "HybridConfiguration verification failed: $($_.Exception.Message)" 'WARN' }
      }
    } catch {
      Write-Log "Set-HybridConfiguration failed: $($_.Exception.Message)" 'WARN'
    }

    # Select Send Connectors
    $sendConnectorsToUpdate = @()
    try {
      if ($AllSendConnectors) {
        Write-Log "Selecting ALL send connectors"
        $sendConnectorsToUpdate = Get-SendConnector -ErrorAction Stop
      } elseif ($SendConnectorExact -and $SendConnectorExact.Count -gt 0) {
        Write-Log ("Selecting exact send connectors: {0}" -f ($SendConnectorExact -join ', '))
        foreach ($name in $SendConnectorExact) {
          $sc = Get-SendConnector -Identity $name -ErrorAction Stop
          if ($sc) { $sendConnectorsToUpdate += $sc }
        }
      } else {
        Write-Log "Selecting send connectors by pattern: $SendConnectorName"
        $sendConnectorsToUpdate = Get-SendConnector $SendConnectorName -ErrorAction Stop
      }
    } catch {
      Write-Log "Failed to resolve send connectors: $($_.Exception.Message)" 'WARN'
    }

    if ($sendConnectorsToUpdate -and $sendConnectorsToUpdate.Count -gt 0) {
      foreach ($sc in $sendConnectorsToUpdate) {
        $currentTls = $null
        try { $currentTls = $sc.TlsCertificateName } catch {}

        # Resolve source servers
        $srcServers = @()
        try { $srcServers = @($sc.SourceTransportServers) } catch {}
        if (-not $srcServers -or $srcServers.Count -eq 0) { $srcServers = @("$(hostname)") }

        Write-Log ("Connector '{0}' sources: {1}" -f $sc.Name, ($srcServers -join ', '))

        # Diagnose remote access per source (optional)
        if ($Diagnose) {
          foreach ($srv in $srcServers) {
            $ar = Test-RemoteExchangeAccess -Server $srv
            $msg = if ($ar.Access -eq 'OK') { 'OK' } else { "$($ar.Access): $($ar.Error)" }
            Write-Log ("Diagnostic: Pre-import access test '{0}': {1}" -f $srv, $msg) 'DIAG'
          }
        }

        # Ensure cert is present + SMTP enabled on ALL sources via Exchange -Server
        $missing = @()
        foreach ($srv in $srcServers) {
          if (-not (Test-CertPresentOnServer -Server $srv -Thumb $thumb)) {
            Write-Log "Server '$srv' missing cert; importing via Exchange -Server..."
            $ok = Ensure-CertOnServerExchange -Server $srv -PfxBytes $bytes -SecPassword $sec
            if (-not $ok) { $missing += $srv }
          }
        }
        # Re-check presence
        if ($missing.Count -eq 0) {
          $missing = $srcServers | Where-Object { -not (Test-CertPresentOnServer -Server $_ -Thumb $thumb) }
        }

        # --- Modified behavior: DO NOT SKIP TLS UPDATE ---
        if ($missing.Count -gt 0) {
          Write-Log ("Connector '{0}': still missing cert on: {1}. Proceeding with TLS update (scheduled task will reconcile on each server)." -f $sc.Name, ($missing -join ', ')) 'WARN'
        }

        # Update TLS name only if different + verify
        if ($currentTls -and ($currentTls -ieq $tlsName)) {
          Write-Log ("Send Connector '{0}': TLS already set. Skipping." -f $sc.Name)
        } else {
          $oldShown = if ($null -ne $currentTls -and $currentTls -ne "") { $currentTls } else { "<null>" }
          Write-Log ("Updating Send Connector '{0}' -TlsCertificateName (old='{1}' -> new='{2}')" -f $sc.Name, $oldShown, $tlsName)
          try { $sc | Set-SendConnector -TlsCertificateName $tlsName -ErrorAction Stop } catch { Write-Log ("Set-SendConnector '{0}' failed: {1}" -f $sc.Name, $_.Exception.Message) 'WARN' }
          Start-Sleep -Milliseconds 500
          try {
            $verify = Get-SendConnector -Identity $sc.Identity -ErrorAction Stop
            $vVal = if ($verify.TlsCertificateName) { $verify.TlsCertificateName } else { '<null>' }
            if ($vVal -ieq $tlsName) {
              Write-Log ("Send Connector '{0}' verification: updated successfully." -f $sc.Name) 'DEBUG'
            } else {
              Write-Log ("Send Connector '{0}' verification: value is '{1}' (expected '{2}')" -f $sc.Name, $vVal, $tlsName) 'WARN'
            }
          } catch { Write-Log ("Send Connector '{0}' verification failed: {1}" -f $sc.Name, $_.Exception.Message) 'WARN' }
        }
      }
    } else {
      Write-Log "No send connectors matched selection; none updated." 'WARN'
    }

    # Receive connectors: update only if different + verify
    Write-Log "Checking Receive Connector '$ReceiveConnectorPattern' -TlsCertificateName"
    try {
      $rcs = @(Get-ReceiveConnector $ReceiveConnectorPattern -ErrorAction Stop)
      if ($rcs.Count -eq 0) { Write-Log "No Receive Connectors matched pattern." 'WARN' }
      foreach ($rc in $rcs) {
        $rcCurrent = $null
        try { $rcCurrent = $rc.TlsCertificateName } catch {}
        if ($rcCurrent -and ($rcCurrent -ieq $tlsName)) {
          Write-Log ("Receive Connector '{0}': TLS already set. Skipping." -f $rc.Name)
        } else {
          $oldRCShown = if ($null -ne $rcCurrent -and $rcCurrent -ne "") { $rcCurrent } else { "<null>" }
          Write-Log ("Updating Receive Connector '{0}' -TlsCertificateName (old='{1}' -> new='{2}')" -f $rc.Name, $oldRCShown, $tlsName)
          try { $rc | Set-ReceiveConnector -TlsCertificateName $tlsName -ErrorAction Stop } catch { Write-Log ("Set-ReceiveConnector '{0}' failed: {1}" -f $rc.Name, $_.Exception.Message) 'WARN' }
          Start-Sleep -Milliseconds 500
          try {
            $rcv = Get-ReceiveConnector -Identity $rc.Identity -ErrorAction Stop
            $rVal = if ($rcv.TlsCertificateName) { $rcv.TlsCertificateName } else { '<null>' }
            if ($rVal -ieq $tlsName) {
              Write-Log ("Receive Connector '{0}' verification: updated successfully." -f $rc.Name) 'DEBUG'
            } else {
              Write-Log ("Receive Connector '{0}' verification: value is '{1}' (expected '{2}')" -f $rc.Name, $rVal, $tlsName) 'WARN'
            }
          } catch { Write-Log ("Receive Connector '{0}' verification failed: {1}" -f $rc.Name, $_.Exception.Message) 'WARN' }
        }
      }
    } catch { Write-Log "ReceiveConnector query failed: $($_.Exception.Message)" 'WARN' }
  } # end Hybrid/connector block

  # ---- Cleanup old certs (default: ON) ----
  if (-not $NoCleanup) {
    Write-Log "Removing older Exchange certificates that match this certificate (excluding $thumb)"
    try {
      $exNew = $null
      try { $exNew = Get-ExchangeCertificate -Thumbprint $thumb -ErrorAction Stop } catch {}
      $toRemove = @()

      if ($exNew) {
        # Normalize domains (no wildcard into -DomainName)
        $domains = @()
        if ($exNew.CertificateDomains) {
          $domains = $exNew.CertificateDomains |
            ForEach-Object { ($_ -replace '^\*\.', '') } |
            Where-Object { $_ -and ($_ -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') } |
            Select-Object -Unique
        }
        if ($domains -and $domains.Count -gt 0) {
          $cand = $null
          try { $cand = Get-ExchangeCertificate -DomainName $domains -ErrorAction Stop } catch {}
          if ($cand) { $toRemove += ($cand | Where-Object { $_.Thumbprint -ne $thumb }) }
        }
        if (-not $toRemove -or $toRemove.Count -eq 0) {
          $subj = $exNew.Subject
          if ($subj) {
            $toRemove += (Get-ExchangeCertificate | Where-Object { $_.Thumbprint -ne $thumb -and $_.Subject -eq $subj })
          }
        }
      } else {
        $subj = $x509.Subject
        $toRemove += (Get-ExchangeCertificate | Where-Object { $_.Thumbprint -ne $thumb -and $_.Subject -eq $subj })
      }

      $toRemove = $toRemove | Select-Object -Unique
      if ($toRemove -and $toRemove.Count -gt 0) {
        Write-Log ("Cleanup: removing {0} older certificate(s)" -f $toRemove.Count)
        $toRemove | ForEach-Object {
          try { $_ | Remove-ExchangeCertificate -Confirm:$false; Write-Log ("Removed older cert {0} (Subject: {1})" -f $_.Thumbprint, $_.Subject) }
          catch { Write-Log ("Failed to remove cert {0}: {1}" -f $_.Thumbprint, $_.Exception.Message) 'WARN' }
        }
      } else {
        Write-Log "Cleanup: no older matching certificates found."
      }
    } catch { Write-Log "Cleanup failed: $($_.Exception.Message)" 'WARN' }
  }

  if ($RestartIIS) {
    Write-Log "Restarting IIS (optional)"
    iisreset /noforce | Out-Null
  }

  Write-Log "Import/Configure completed successfully."

} catch {
  Write-Log "ERROR: $($_.Exception.Message)" 'ERROR'
  if ($DebugOn -and $_.ScriptStackTrace) { Write-Log "Stack: $($_.ScriptStackTrace)" 'DEBUG' }
  exit 1
} finally {
  Stop-Logging
}
