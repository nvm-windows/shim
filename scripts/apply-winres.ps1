param(
  [Parameter(Mandatory = $true)]
  [string]$ExePath,
  [Parameter(Mandatory = $true)]
  [string]$WinresPath
)

$ErrorActionPreference = "Stop"

function Resolve-RcEditPath {
  param(
    [string]$ProvidedPath = $env:RCEDIT_PATH
  )

  if (-not [string]::IsNullOrWhiteSpace($ProvidedPath)) {
    $resolvedProvided = [System.IO.Path]::GetFullPath($ProvidedPath)
    if (Test-Path -LiteralPath $resolvedProvided) {
      return $resolvedProvided
    }
    throw "RCEDIT_PATH is set but file was not found at: $resolvedProvided"
  }

  $localPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".tools\rcedit-x64.exe"))
  if (Test-Path -LiteralPath $localPath) {
    return $localPath
  }

  throw "rcedit not found. Set RCEDIT_PATH or place rcedit at: $localPath"
}

function Invoke-External {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  if ([string]::IsNullOrWhiteSpace($FilePath) -or !(Test-Path -LiteralPath $FilePath)) {
    throw "Executable not found at: $FilePath"
  }

  $maxAttempts = 3
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -eq 0) { return }
    if ($attempt -lt $maxAttempts) {
      Write-Warning "rcedit attempt $attempt failed (exit $LASTEXITCODE). Retrying in 1s..."
      Start-Sleep -Seconds 1
    }
  }
  throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
}

function Resolve-MtExe {
  $cmd = Get-Command mt.exe -ErrorAction SilentlyContinue
  if ($cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
    $source = [string]$cmd.Source
    if (Test-Path -LiteralPath $source) {
      return [System.IO.Path]::GetFullPath($source)
    }
  }

  $kitsRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
  if (!(Test-Path $kitsRoot)) {
    return $null
  }

  $candidates = Get-ChildItem -Path $kitsRoot -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName "x64\mt.exe" } |
    Where-Object { Test-Path $_ } |
    Sort-Object -Descending

  if ($candidates.Count -gt 0) {
    return [System.IO.Path]::GetFullPath($candidates[0])
  }

  return $null
}

function Escape-Xml {
  param([string]$Value)

  if ($null -eq $Value) {
    return ""
  }

  return [System.Security.SecurityElement]::Escape($Value)
}

function Get-SafeAssemblyIdentityName {
  param([string]$Name)

  $raw = if ([string]::IsNullOrWhiteSpace($Name)) { "nvm.windows.shim" } else { $Name.Trim() }
  $safe = [System.Text.RegularExpressions.Regex]::Replace($raw, "[^A-Za-z0-9._-]", ".")
  $safe = [System.Text.RegularExpressions.Regex]::Replace($safe, "[.]{2,}", ".")
  $safe = $safe.Trim('.')

  if ([string]::IsNullOrWhiteSpace($safe)) {
    return "nvm.windows.shim"
  }

  return $safe
}

$resolvedExePath = [System.IO.Path]::GetFullPath($ExePath)
$resolvedWinresPath = [System.IO.Path]::GetFullPath($WinresPath)

if (!(Test-Path $resolvedExePath)) {
  throw "Executable not found at $resolvedExePath"
}

if (!(Test-Path $resolvedWinresPath)) {
  throw "winres.json not found at $resolvedWinresPath"
}

$json = Get-Content -LiteralPath $resolvedWinresPath -Raw | ConvertFrom-Json -AsHashtable
$baseDir = Split-Path -Parent $resolvedWinresPath

$rcEdit = Resolve-RcEditPath

$versionNode = $null
if ($json.ContainsKey('RT_VERSION') -and $json['RT_VERSION'] -is [hashtable]) {
  $rtVersion = $json['RT_VERSION']
  if ($rtVersion.ContainsKey('#1') -and $rtVersion['#1'] -is [hashtable]) {
    $rtVersionEn = $rtVersion['#1']
    if ($rtVersionEn.ContainsKey('0000') -and $rtVersionEn['0000'] -is [hashtable]) {
      $versionNode = $rtVersionEn['0000']
    }
  }
}

$versionInfo = @{}
$fixed = @{}
if ($versionNode) {
  if ($versionNode.ContainsKey('info') -and $versionNode['info'] -is [hashtable]) {
    $infoNode = $versionNode['info']
    if ($infoNode.ContainsKey('0409') -and $infoNode['0409'] -is [hashtable]) {
      $versionInfo = $infoNode['0409']
    }
  }
  if ($versionNode.ContainsKey('fixed') -and $versionNode['fixed'] -is [hashtable]) {
    $fixed = $versionNode['fixed']
  }
}

if ($fixed['file_version']) {
  Invoke-External -FilePath $rcEdit -Arguments @($resolvedExePath, '--set-file-version', "$($fixed['file_version'])")
}

if ($fixed['product_version']) {
  Invoke-External -FilePath $rcEdit -Arguments @($resolvedExePath, '--set-product-version', "$($fixed['product_version'])")
}

foreach ($key in @('Comments', 'CompanyName', 'FileDescription', 'FileVersion', 'InternalName', 'LegalCopyright', 'LegalTrademarks', 'OriginalFilename', 'PrivateBuild', 'ProductName', 'ProductVersion', 'SpecialBuild')) {
  $val = $versionInfo[$key]
  if ($null -ne $val -and "$val" -ne "") {
    Invoke-External -FilePath $rcEdit -Arguments @($resolvedExePath, '--set-version-string', $key, "$val")
  }
}

$iconRel = $null
if ($json.ContainsKey('RT_GROUP_ICON') -and $json['RT_GROUP_ICON'] -is [hashtable]) {
  $groupIcon = $json['RT_GROUP_ICON']
  if ($groupIcon.ContainsKey('#1') -and $groupIcon['#1'] -is [hashtable]) {
    $groupIconEn = $groupIcon['#1']
    if ($groupIconEn.ContainsKey('0000')) {
      $iconRel = $groupIconEn['0000']
    }
  }
}
if ($iconRel) {
  $iconPath = [System.IO.Path]::GetFullPath((Join-Path $baseDir $iconRel))
  if (!(Test-Path $iconPath)) {
    throw "Icon file not found at $iconPath"
  }
  Invoke-External -FilePath $rcEdit -Arguments @($resolvedExePath, '--set-icon', $iconPath)
}

$manifestNode = $null
if ($json.ContainsKey('RT_MANIFEST') -and $json['RT_MANIFEST'] -is [hashtable]) {
  $manifest = $json['RT_MANIFEST']
  if ($manifest.ContainsKey('#1') -and $manifest['#1'] -is [hashtable]) {
    $manifestEn = $manifest['#1']
    if ($manifestEn.ContainsKey('0409') -and $manifestEn['0409'] -is [hashtable]) {
      $manifestNode = $manifestEn['0409']
    }
  }
}
if ($manifestNode) {
  $mtExe = Resolve-MtExe
  if ($mtExe -and (Test-Path -LiteralPath $mtExe)) {
    $identityName = Get-SafeAssemblyIdentityName -Name "$($manifestNode['identity']['name'])"
    $identityVersion = "$($manifestNode['identity']['version'])".Trim()
    # SxS requires exactly four numeric parts (a.b.c.d); pad or default as needed.
    if ([string]::IsNullOrWhiteSpace($identityVersion)) {
      $identityVersion = "1.0.0.0"
    } else {
      $parts = $identityVersion -split '\.'
      while ($parts.Count -lt 4) { $parts += "0" }
      $identityVersion = ($parts[0..3] | ForEach-Object { if ($_ -match '^\d+$') { $_ } else { "0" } }) -join "."
    }
    $description = Escape-Xml -Value "$($manifestNode['description'])"
    if ([string]::IsNullOrWhiteSpace($description)) {
      $description = "NVM for Windows shim"
    }

    $level = "asInvoker"
    if ($manifestNode['execution-level']) {
      $raw = "$($manifestNode['execution-level'])".Trim().ToLowerInvariant()
      if ($raw -eq 'highest available') { $level = 'highestAvailable' }
      elseif ($raw -eq 'require administrator') { $level = 'requireAdministrator' }
    }

    $uiAccess = "false"
    if ($manifestNode['ui-access']) { $uiAccess = "true" }

    $manifestXml = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="$(Escape-Xml -Value $identityName)" version="$(Escape-Xml -Value $identityVersion)" processorArchitecture="*"/>
  <description>$description</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="$level" uiAccess="$uiAccess"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"@

    $tmpManifest = Join-Path $env:TEMP ("winres-manifest-" + [System.Guid]::NewGuid().ToString("N") + ".xml")
    $manifestXml | Out-File -LiteralPath $tmpManifest -Encoding utf8
    try {
      Invoke-External -FilePath $mtExe -Arguments @('-manifest', $tmpManifest, "-outputresource:$resolvedExePath;#1")
    } finally {
      Remove-Item -LiteralPath $tmpManifest -Force -ErrorAction SilentlyContinue
    }
  } else {
    Write-Warning "Valid mt.exe was not found. Manifest update skipped for $resolvedExePath"
  }
}
