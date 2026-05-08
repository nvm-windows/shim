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

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
  }
}

function Resolve-MtExe {
  $cmd = Get-Command mt.exe -ErrorAction SilentlyContinue
  if ($cmd) {
    return $cmd.Source
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
    return $candidates[0]
  }

  return $null
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
  if ($mtExe) {
    $identityName = $manifestNode['identity']['name']
    $identityVersion = $manifestNode['identity']['version']
    $description = $manifestNode['description']

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
  <assemblyIdentity type="win32" name="$identityName" version="$identityVersion" processorArchitecture="*"/>
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
    Write-Warning "mt.exe was not found. Manifest update skipped for $resolvedExePath"
  }
}
