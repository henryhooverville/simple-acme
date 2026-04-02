# HA renewal mechanism in the event of an exchange server failure, operate with --renew --force --verbose
param(
  [string]$WacsPath = "C:\Program Files\simple-acme\wacs.exe",
  [string]$Domains  = "*.example.com,example.com",
  [string]$Token  = "vault://json/cloudflare-token",
  [string]$Friendly = "example.com"
)

# 1) Create the renewal
$createArgs = @(
  "--target","manual",
  "--host",$Domains,
  "--validation","cloudflare",
  "--validationmode","dns-01",
  "--cloudflareapitoken",$Token,
  "--store","none",
  "--installation","none",
  "--friendlyname",$Friendly,
  "--accepttos","--verbose"
)
& $WacsPath $createArgs
if ($LASTEXITCODE -ne 0) { throw "Creation failed ($LASTEXITCODE)" }

# 2) Trigger the renewal immediately on recovery Exchange server
$renewArgs = @("--renew","--force","--verbose","--friendlyname",$Friendly)
& $WacsPath $renewArgs
exit $LASTEXITCODE