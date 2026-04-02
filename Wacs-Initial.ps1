# Purpose: Create the initial win-acme renewal for *.example.com,example.com using Cloudflare DNS-01
#          Export a PFX to DFS; keep secrets in the existing JSON vault.
#          This renewal will be reused by future `wacs.exe --renew` runs.

$wacs = "C:\Program Files\simple-acme\wacs.exe"

# Paths (adjust if you prefer different folders/filenames)
$shareRoot   = "\\NETWORKDRIVE\Share"
$pfxOutDir   = Join-Path $shareRoot "Certs"
$script   = "C:\Program Files\simple-acme\Scripts\Wacs-Export.ps1"

# Ensure the export folder exists (fails silently if already there)
if (-not (Test-Path $pfxOutDir)) { New-Item -Path $pfxOutDir -ItemType Directory -Force | Out-Null }

# Build command-line arguments for unattended creation
$wacsArgs = @(
  # Select target and identifiers (unattended creation requires --target)
  "--target",          "manual",
  "--host",            "*.example.com,example.com",

  # IF APPLICABLE Use Cloudflare DNS-01 validation plugin (requires the Cloudflare validation plugin)
  "--validation",      "cloudflare",
  "--validationmode",  "dns-01",
  "--cloudflareapitoken", "vault://json/cloudflare-token",

  # Export a PFX to DFS using the PFX file store
  "--store",           "pfxfile",
  "--pfxfilepath",     $pfxOutDir,
  "--pfxpassword",     "vault://json/pfx-password",

  # (Optional) Post-installation hook; keep for later Exchange steps
  "--installation",    "script",
  "--script",          $script,
  # Pass placeholders; they’re resolved by simple-acme before invoking your script.
  "--scriptparameters", " -NewCertThumbprint '{CertThumbprint}' -OutputRoot '\\NETWORKDRIVE\Share' -RequiredDomainsCsv '*.example.com,example.com' -ExportPfxPassword '{CachePassword}'",
  "--verbose"

# Execute
& $wacs $wacsArgs