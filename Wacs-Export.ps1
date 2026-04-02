<#
.SYNOPSIS
Post-renewal export script. Exports the renewed certificate to \Archive (dated) and \Certs (latest).

.DESCRIPTION
- Loads the certificate from the newest cycled .pfx in <OutputRoot>\Certs using passwords from a secrets file.
- Validates required SANs.
- Exports dated artifacts to <OutputRoot>\Archive and copies "current" to <OutputRoot>\Certs.
- PFX export password resolution order:
  1) -ExportPfxPassword (explicit)
  2) Matching Key in export-secrets file (BaseName, any SAN), then "default"
  3) If imported from \Certs, reuse the password that worked
  -> Throws if no password resolved.

.EXECUTION
- You can run the script in two ways
- .\Wacs-Export.ps1 -NewCertThumbprint "<thumbprint>" -OutputRoot "\\NETWORKDRIVE\Share" -RequiredDomainsCsv "*.example.com,example.com"
- or in the historic way accounting for deprecated cachepasswords
- .\Wacs-Export.ps1 "{thumbprint}" "" "" "" "NETWORKDRIVE\Share" "*.example.com,example.com"

SECRETS FORMAT (preferred):
[
  { "Key": "default",   "Secret": "YourStrongDefaultPass#2026" },
  { "Key": "example.com",  "Secret": "AnotherPass1!" },
  { "Key": "*.example.com","Secret": "WildcardPass1!" }
]

Back-compat (also accepted):
{
  "default": { "pfxPassword": "..." },
  "example.com": "..."
}

NOTES
- Run as Administrator or SYSTEM.
- Default secrets file is <OutputRoot>\export-secrets.json (override with -SecretsPath).
- To avoid any WACS coupling, this script ignores cache parameters and does not use WACS cache passwords.
#>

[CmdletBinding()]
param(
    # 0 - Thumbprint of the renewed certificate (kept for compatibility; used only if -AllowStoreFallback)
    [Parameter(Position=0, Mandatory=$true)]
    [string] $NewCertThumbprint,

    # 1 - (Deprecated, ignored) WACS cache .pfx
    [Parameter(Position=1, Mandatory=$false)]
    [string] $CacheFile,

    # 2 - (Deprecated, ignored) WACS cache password
    [Parameter(Position=2, Mandatory=$false)]
    [string] $CachePassword,

    # 3 - Friendly name (optional, informational)
    [Parameter(Position=3, Mandatory=$false)]
    [string] $FriendlyName,

    # 4 - Output root (UNC or local). Script creates \Archive and \Certs here.
    [Parameter(Position=4, Mandatory=$true)]
    [string] $OutputRoot,

    # 5 - Comma-separated required SANs (e.g., "domain.com,*.domain.com")
    [Parameter(Position=5, Mandatory=$true)]
    [string] $RequiredDomainsCsv,

    # 6 - Optional explicit path to secrets file. Defaults to <OutputRoot>\export-secrets.json
    [Parameter(Position=6, Mandatory=$false)]
    [string] $SecretsPath,

    # 7 - Optional explicit export password (overrides secrets)
    [Parameter(Position=7, Mandatory=$false)]
    [string] $ExportPfxPassword,

    # Enable verbose debug logging
    [switch] $DebugOn,

    # Optional: allow fallback to Windows cert store by thumbprint
    [switch] $AllowStoreFallback
)

# ----------------------- Logging and safety -----------------------
if ($DebugOn) {
    $DebugPreference   = 'Continue'
    $VerbosePreference = 'Continue'
}
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = "INFO")
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    switch ($Level) {
        'INFO'  { Write-Host    "[$stamp][INFO ] $Message" }
        'WARN'  { Write-Warning "[$stamp][WARN ] $Message" }
        'ERROR' { Write-Error   "[$stamp][ERROR] $Message" }
        'DEBUG' { if ($DebugOn) { Write-Host "[$stamp][DEBUG] $Message" -ForegroundColor DarkGray } }
    }
}

function Require-AdminOrSystem {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin  = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $id.Name -eq "NT AUTHORITY\SYSTEM"
    if (-not ($isAdmin -or $isSystem)) {
        throw "Run as Administrator or SYSTEM."
    }
    Write-Log "Running as $($id.Name)"
}

function Ensure-Folder {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Log "Created folder $Path"
    }
    (Resolve-Path -LiteralPath $Path).Path
}

# ----------------------- Certificate helpers -----------------------
function Get-CertificateFromStores {
    param([string]$Thumbprint)
    $thumb = $Thumbprint -replace '\s','' -replace '[^0-9A-Fa-f]',''
    $stores = @(
        'Cert:\LocalMachine\My',
        'Cert:\LocalMachine\WebHosting'
    )
    foreach ($store in $stores) {
        try {
            Write-Log "Searching store $store for thumbprint $thumb" 'DEBUG'
            $c = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
                 Where-Object { $_.Thumbprint -ieq $thumb } |
                 Select-Object -First 1
            if ($c) {
                Write-Log "Found certificate in $store"
                return $c
            }
        } catch {
            Write-Log "Error accessing $store $($_.Exception.Message)" 'WARN'
        }
    }
    return $null
}

function Get-RequiredDomains {
    param([string]$Csv)
    ($Csv -split ',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' } | Sort-Object -Unique
}

function Get-CertDomains {
    <#
      Returns lower-cased list of SAN DNS names (plus CN as fallback) from a cert.
      Note: Detect SAN by OID to avoid localized FriendlyName lookups.
    #>
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $dns = New-Object System.Collections.Generic.List[string]
    $cn = $Cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
    if ($cn) { [void]$dns.Add($cn.ToLowerInvariant()) }
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq '2.5.29.17') {
            $data = $ext.Format($true)
            $data -split "`n" | ForEach-Object {
                $line = $_.Trim()
                if ($line -match '^DNS Name=(.+)$') {
                    [void]$dns.Add($Matches[1].Trim().ToLowerInvariant())
                }
            }
        }
    }
    $dns | Sort-Object -Unique
}

function Validate-RequiredDomainsPresent {
    param([string[]]$Required, [string[]]$Present)
    $missing = @()
    foreach ($r in $Required) { if ($Present -notcontains $r) { $missing += $r } }
    return ,$missing
}

function Choose-BaseName {
    param([string[]]$Required, [string[]]$Present)
    $candidate = $Required | Where-Object { $_ -notmatch '^\*\.' } | Where-Object { $Present -contains $_ } | Select-Object -First 1
    if (-not $candidate) { $candidate = $Present | Where-Object { $_ -notmatch '^\*\.' } | Select-Object -First 1 }
    if (-not $candidate) { $candidate = ($Present | Select-Object -First 1) }
    if ($candidate -like '*.*') { return $candidate -replace '^\*\.', '' }
    return $candidate
}

function Get-PreferredPfx {
    <#
      Attempts to find the most appropriate PFX for the current certificate based on baseName.
      Search order:
        1) <certsDir>\<baseName>.pfx
        2) <certsDir>\_.<baseName>.pfx   (wildcard-friendly naming, e.g., *.example.com -> _.example.com.pfx)
        3) First match of "*<baseName>*.pfx" by most recent write time
        4) Fallback: newest "*.pfx" in <certsDir>

      Returns: FileInfo of the chosen PFX, or $null if none exist.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$CertsDir,
        [Parameter(Mandatory=$true)][string]$BaseName
    )

    # 1) Exact "<baseName>.pfx"
    $exact = Join-Path $CertsDir ("{0}.pfx" -f $BaseName)
    if (Test-Path -LiteralPath $exact) {
        return Get-Item -LiteralPath $exact
    }

    # 2) Wildcard-friendly "_.<baseName>.pfx" (convention for *.domain.tld)
    $underscore = Join-Path $CertsDir ("_.{0}.pfx" -f $BaseName)
    if (Test-Path -LiteralPath $underscore) {
        return Get-Item -LiteralPath $underscore
    }

    # 3) Any PFX that contains the baseName in its filename (most recent)
    $patternMatches = Get-ChildItem -LiteralPath $CertsDir -Filter '*.pfx' -File -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -like ("*{0}*" -f $BaseName) } |
                      Sort-Object LastWriteTime -Descending
    if ($patternMatches -and $patternMatches.Count -gt 0) {
        return $patternMatches[0]
    }

    # 4) Fallback: newest PFX in the folder
    $newest = Get-ChildItem -LiteralPath $CertsDir -Filter '*.pfx' -File -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($newest) { return $newest }

    return $null
}

# ----------------------- Export helpers -----------------------
function Export-LeafCer {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$CerPath)
    Export-Certificate -Cert $Cert -FilePath $CerPath -Type CERT -Force | Out-Null
}

function To-Pem {
    param([byte[]]$Raw, [string]$Header, [string]$Footer)
    $b64 = [System.Convert]::ToBase64String($Raw)
    $chunks = ($b64 -split "(.{1,64})" | Where-Object { $_ -ne '' })
    return @($Header) + $chunks + @($Footer) -join "`r`n"
}

function Export-LeafPem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$PemPath)
    $raw = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $pem = To-Pem -Raw $raw -Header '-----BEGIN CERTIFICATE-----' -Footer '-----END CERTIFICATE-----'
    Set-Content -LiteralPath $PemPath -Value $pem -NoNewline -Encoding ascii
}

function Is-SelfSigned {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    return ($Cert.Subject -eq $Cert.Issuer)
}

function Get-CertChain {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreWrongUsage
    [void]$chain.Build($Cert)
    return $chain.ChainElements | ForEach-Object { $_.Certificate }
}

function Export-FullChainPem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$FullChainPemPath)
    $chain = Get-CertChain -Cert $Cert
    if ($chain.Count -gt 0 -and (Is-SelfSigned -Cert $chain[-1])) {
        $chain = $chain[0..($chain.Count-2)]
    }
    $parts = @()
    foreach ($c in $chain) {
        $parts += To-Pem -Raw $c.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) -Header '-----BEGIN CERTIFICATE-----' -Footer '-----END CERTIFICATE-----'
    }
    Set-Content -LiteralPath $FullChainPemPath -Value ($parts -join "`r`n") -NoNewline -Encoding ascii
}

function Export-Pfx {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$DestPfxPath, [string]$Password)
    if (-not $Password) { throw "Export PFX password not resolved. Check secrets file or pass -ExportPfxPassword." }
    
    $sec = ConvertTo-SecureString -String $Password -AsPlainText -Force
    
    # 1. Open the temporary Current User store
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
    $store.Open("ReadWrite")
    
    try {
        # 2. Add the cert so the native cmdlet can "see" the private key
        $store.Add($Cert)
        
        # 3. Natively export it with the NEW password
        Export-PfxCertificate -Cert $Cert -FilePath $DestPfxPath -Password $sec -Force | Out-Null
    }
    finally {
        # 4. Clean up immediately so no zombie keys are left behind
        $store.Remove($Cert)
        $store.Close()
    }
}

# ----------------------- Secrets helpers -----------------------

# Encoding- and provider-safe loader
function Load-Secrets {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        # Normalize to a pure filesystem path (strip provider prefix)
        $fsPath = (Get-Item -LiteralPath $Path -ErrorAction Stop).FullName

        $bytes = [System.IO.File]::ReadAllBytes($fsPath)
        if (-not $bytes -or $bytes.Length -eq 0) { return $null }

        function Decode-Bytes([byte[]]$b) {
            if     ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return [System.Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) } # UTF-8 BOM
            elseif ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE)                     { return [System.Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2) } # UTF-16 LE
            elseif ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF)                     { return [System.Text.Encoding]::BigEndianUnicode.GetString($b, 2, $b.Length - 2) } # UTF-16 BE
            else                                                                                 { return [System.Text.Encoding]::UTF8.GetString($b) } # assume UTF-8 no BOM
        }

        $raw = Decode-Bytes $bytes
        if (-not $raw -or -not $raw.Trim()) { return $null }

        return $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Failed to parse secrets file at '$Path' $($_.Exception.Message)"
    }
}

# Normalize secrets to a list of @{ Key=..., Secret=... } (case-insensitive, trimmed)
function Secrets-GetEntries {
    param([object]$Secrets)
    $entries = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Secrets) { return @() }

    if ($Secrets -is [System.Array]) {
        foreach ($it in $Secrets) {
            if ($it -ne $null -and ($it.PSObject.Properties.Name -contains 'Key') -and ($it.PSObject.Properties.Name -contains 'Secret')) {
                $key = ([string]$it.Key).Trim()
                $sec = ([string]$it.Secret)
                if ($key -and $sec) { [void]$entries.Add([ordered]@{ Key=$key; Secret=$sec }) }
            }
        }
    } else {
        # Back-compat: object with named properties -> entries
        foreach ($p in $Secrets.PSObject.Properties) {
            $name = ([string]$p.Name).Trim()
            $node = $p.Value
            $pw = $null
            if     ($node -is [string])                                                   { $pw = [string]$node }
            elseif ($node -ne $null -and $node.PSObject.Properties.Name -contains 'pfxPassword') { $pw = [string]$node.pfxPassword }
            if ($name -and $pw) { [void]$entries.Add([ordered]@{ Key=$name; Secret=$pw }) }
        }
    }

    return ,$entries
}

# Build candidate passwords list (unique, default-first)
function Get-SecretPasswordCandidates {
    param([object[]]$Entries)
    $list = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Entries -or $Entries.Count -eq 0) { return @() }

    foreach ($e in $Entries) {
        $pw = [string]$e.Secret
        if ($pw -and -not $list.Contains($pw)) { [void]$list.Add($pw) }
    }

    # Move default's secret to the front if present
    $default = $Entries | Where-Object { $_.Key -ieq 'default' } | Select-Object -First 1
    if ($default) {
        $defPw = [string]$default.Secret
        if ($defPw -and $list.Contains($defPw)) {
            $list.Remove($defPw) | Out-Null
            $list.Insert(0, $defPw)
        }
    }
    return $list
}

# Resolve export password: BaseName -> any SAN -> default -> ImportPw -> ParamOverride first
function Resolve-ExportPfxPassword {
    param(
        [object[]]$Entries,
        [string]$BaseName,
        [string[]]$PresentDomains,
        [string]$ParamOverride,
        [string]$ImportPw
    )

    if ($ParamOverride) { return $ParamOverride }

    function Find-Secret([string]$key, [object[]]$entries) {
        if (-not $key) { return $null }
        $norm = $key.Trim()
        $hit = $entries | Where-Object { $_.Key.Trim() -ieq $norm } | Select-Object -First 1
        if ($hit) { return [string]$hit.Secret }
        return $null
    }

    if ($Entries -and $Entries.Count -gt 0) {
        $pw = Find-Secret -key $BaseName -entries $Entries
        if ($pw) { return $pw }

        foreach ($d in $PresentDomains) {
            $pw = Find-Secret -key $d -entries $Entries
            if ($pw) { return $pw }
        }

        $pw = Find-Secret -key 'default' -entries $Entries
        if ($pw) { return $pw }
    }

    if ($ImportPw) { return $ImportPw }
    return $null
}

# Attempt to import a PFX with a set of candidate passwords (provider-safe path)
function Try-ImportPfx {
    param(
        [string]$PfxPath,
        [string[]]$CandidatePasswords,
        [ref]$UsedPassword
    )
    $flags  = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet `
            -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet `
            -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable

    $fsPfx = (Get-Item -LiteralPath $PfxPath -ErrorAction Stop).FullName
    $bytes = [System.IO.File]::ReadAllBytes($fsPfx)

    foreach ($pw in $CandidatePasswords) {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($bytes, $pw, $flags)
            $UsedPassword.Value = $pw
            return $cert
        } catch {
            Write-Log "Password attempt failed for $fsPfx (masked)." 'DEBUG'
        }
    }

    # Last attempt: empty password
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($bytes, "", $flags)
        $UsedPassword.Value = ""
        return $cert
    } catch {
        Write-Log "Empty password attempt failed for $fsPfx." 'DEBUG'
    }

    return $null
}

# ----------------------- Main -----------------------
try {
    Require-AdminOrSystem

    # Log incoming params (safe subset)
    Write-Log "Thumbprint $NewCertThumbprint"
    if ($FriendlyName) { Write-Log "FriendlyName $FriendlyName" }
    Write-Log "OutputRoot $OutputRoot"
    Write-Log "RequiredDomainsCsv $RequiredDomainsCsv"

    # Prepare output folders
    $outRoot    = Ensure-Folder -Path $OutputRoot
    $archiveDir = Ensure-Folder -Path (Join-Path $outRoot 'Archive')
    $certsDir   = Ensure-Folder -Path (Join-Path $outRoot 'Certs')

    # Secrets path default (native separate file)
    if (-not $SecretsPath -or $SecretsPath.Trim() -eq '') {
        $SecretsPath = Join-Path $outRoot 'export-secrets.json'
    }
    Write-Log "Secrets path: $SecretsPath"

    # Load secrets early (Key/Secret format supported)
    $secretsRaw = Load-Secrets -Path $SecretsPath
    $secretEntries = Secrets-GetEntries -Secrets $secretsRaw
    if ($DebugOn) {
        $keys = if ($secretEntries) { ($secretEntries | ForEach-Object { $_.Key }) -join ', ' } else { '(none)' }
        Write-Log "secrets keys detected: $keys" 'DEBUG'
    }
    if (-not $secretEntries -or $secretEntries.Count -eq 0) {
        Write-Log "No usable secrets found. Import/export will require -ExportPfxPassword." 'WARN'
    }
    $secretCandidates = Get-SecretPasswordCandidates -Entries $secretEntries

    # Parse required domains
    $requiredDomains = Get-RequiredDomains -Csv $RequiredDomainsCsv
    Write-Log "Required domains: $($requiredDomains -join ', ')"

    # ---------------- Acquire the certificate (Certs only by default) ----------------
    $cert = $null
    $usedImportPw = $null

    # --- Build a candidate list of PFX files to try in order ---

# Use RequiredDomains to form a tentative base and detect wildcard intent
$requiredDomains = Get-RequiredDomains -Csv $RequiredDomainsCsv

# Tentative base from required domains (prefer non-wildcard; else first entry)
$tentativeBase = ($requiredDomains | Where-Object { $_ -notmatch '^\*\.' } | Select-Object -First 1)
if (-not $tentativeBase) { $tentativeBase = ($requiredDomains | Select-Object -First 1) }
if ($tentativeBase -like '*.*') { $tentativeBase = ($tentativeBase -replace '^\*\.', '') }

# Detect wildcard presence
$hasWildcard = ($requiredDomains | Where-Object { $_ -match '^\*\.' }) -ne $null

# Candidate list
$candidates = New-Object System.Collections.Generic.List[System.IO.FileInfo]

# Known names
$exactPath      = Join-Path $certsDir ("{0}.pfx" -f $tentativeBase)      # example.com.pfx
$underscorePath = Join-Path $certsDir ("_.{0}.pfx" -f $tentativeBase)    # _.example.com.pfx

# Prefer underscore first if wildcard SANs exist; else exact first
$orderedPreferred = if ($hasWildcard) { @($underscorePath, $exactPath) } else { @($exactPath, $underscorePath) }

foreach ($p in $orderedPreferred) {
    if (Test-Path -LiteralPath $p) {
        $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
        if ($item) { [void]$candidates.Add($item) }
    }
}

# Any *<base>* matches (most recent first), excluding duplicates
$patternMatches = Get-ChildItem -LiteralPath $certsDir -Filter '*.pfx' -File -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like ("*{0}*" -f $tentativeBase) } |
                  Sort-Object LastWriteTime -Descending

foreach ($m in $patternMatches) {
    if (-not ($candidates | Where-Object { $_.FullName -ieq $m.FullName })) {
        [void]$candidates.Add($m)
    }
}

# Fallback: newest PFX if nothing else
$newest = Get-ChildItem -LiteralPath $certsDir -Filter '*.pfx' -File -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($newest -and -not ($candidates | Where-Object { $_.FullName -ieq $newest.FullName })) {
    [void]$candidates.Add($newest)
}

if ($DebugOn) {
    Write-Log ("PFX candidate order: {0}" -f (($candidates | ForEach-Object { $_.Name }) -join ' | ')) 'DEBUG'
}

# --- Try import with all candidates and all secrets ---
$cert = $null
$usedImportPw = $null
foreach ($file in $candidates) {
    Write-Log "Attempting to import candidate PFX: $($file.FullName)"
    $pwRef = [ref] $null
    $cert = Try-ImportPfx -PfxPath $file.FullName -CandidatePasswords $secretCandidates -UsedPassword $pwRef
    if ($cert) {
        $usedImportPw = $pwRef.Value
        Write-Log "Imported certificate from candidate PFX"
        break
    } else {
        Write-Log "Failed to import candidate: $($file.Name) with provided secrets" 'WARN'
    }
}

if (-not $cert) {
    throw "Certificate not found. Could not import from \Certs."
}
    # Inspect SANs/subjects
    $present = Get-CertDomains -Cert $cert
    Write-Log "Certificate SAN/subjects: $($present -join ', ')"
    $missing = Validate-RequiredDomainsPresent -Required $requiredDomains -Present $present
    if ($missing.Count -gt 0) {
        Write-Log "Certificate is missing required SAN(s): $($missing -join ', ')" 'WARN'
    }

    # Determine base filename
    $baseName = Choose-BaseName -Required $requiredDomains -Present $present
    if (-not $baseName) { $baseName = $NewCertThumbprint.ToLower() }
    Write-Log "Base name for files: $baseName"

    $timestamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $archiveBase = Join-Path $archiveDir ("{0}_{1}" -f $baseName, $timestamp)

    # Resolve export password
    if ($DebugOn) {
        Write-Log ("Matching keys sought -> BaseName: {0}; SANs: {1}" -f $baseName, ($present -join ', ')) 'DEBUG'
        $keys = if ($secretEntries) { ($secretEntries | ForEach-Object { $_.Key }) -join ', ' } else { '(none)' }
        Write-Log ("Available secret keys -> {0}" -f $keys) 'DEBUG'

        $paramOverrideFlag = if ([string]::IsNullOrEmpty($ExportPfxPassword)) { 'No' } else { 'Yes' }
        $importPwFlag      = if ([string]::IsNullOrEmpty($usedImportPw))      { 'No' } else { 'Yes' }
        Write-Log (
            "Password resolution inputs -> BaseName: {0}; ParamOverride: {1}; ImportPwPresent: {2}" -f `
            $baseName, $paramOverrideFlag, $importPwFlag
        ) 'DEBUG'
    }

    $resolvedExportPw = Resolve-ExportPfxPassword `
        -Entries        $secretEntries `
        -BaseName       $baseName `
        -PresentDomains $present `
        -ParamOverride  $ExportPfxPassword `
        -ImportPw       $usedImportPw

    if (-not $resolvedExportPw) {
        throw "Export PFX password not found. Provide -ExportPfxPassword or configure a secrets entry (default/BaseName/SAN) in $SecretsPath."
    }

    $pwSource = '(none)'
    if ($ExportPfxPassword) { $pwSource = 'parameter' }
    elseif ($usedImportPw -and $resolvedExportPw -eq $usedImportPw) { $pwSource = 'import password' }
    elseif ($secretEntries) { $pwSource = 'secrets file' }
    Write-Log "Resolved export PFX password source: $pwSource"

    # Paths for artifacts (Archive)
    $archivePfx     = "${archiveBase}.pfx"
    $archiveCer     = "${archiveBase}.cer"
    $archivePem     = "${archiveBase}.pem"
    $archiveFullPem = "${archiveBase}-fullchain.pem"

    # Export PFX (policy password)
    Export-Pfx -Cert $cert -DestPfxPath $archivePfx -Password $resolvedExportPw
    Write-Log "Archived PFX: $archivePfx"

    # Export CER/PEM (leaf) and PEM (full chain, root excluded)
    Export-LeafCer      -Cert $cert -CerPath $archiveCer
    Export-LeafPem      -Cert $cert -PemPath $archivePem
    Export-FullChainPem -Cert $cert -FullChainPemPath $archiveFullPem
    Write-Log "Archived CER/PEM: $archiveCer ; $archivePem ; $archiveFullPem"

    # Copy "current" artifacts to \Certs (overwrite)
    $currentPfx     = Join-Path $certsDir ("{0}.pfx" -f $baseName)
    $currentCer     = Join-Path $certsDir ("{0}.cer" -f $baseName)
    $currentPem     = Join-Path $certsDir ("{0}.pem" -f $baseName)
    $currentFullPem = Join-Path $certsDir ("{0}-fullchain.pem" -f $baseName)

    Copy-Item -LiteralPath $archivePfx     -Destination $currentPfx     -Force
    Copy-Item -LiteralPath $archiveCer     -Destination $currentCer     -Force
    Copy-Item -LiteralPath $archivePem     -Destination $currentPem     -Force
    Copy-Item -LiteralPath $archiveFullPem -Destination $currentFullPem -Force

    Write-Log "Updated current \Certs:"
    Write-Log "  $currentPfx"
    Write-Log "  $currentCer"
    Write-Log "  $currentPem"
    Write-Log "  $currentFullPem"

    Write-Log "Completed successfully."
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)" 'ERROR'
    if ($DebugOn -and $_.ScriptStackTrace) {
        Write-Log "Stack: $($_.ScriptStackTrace)" 'DEBUG'
    }
    exit 1
}