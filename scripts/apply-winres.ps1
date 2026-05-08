param(
  [Parameter(Mandatory = $true)]
  [string]$ExePath,
  [Parameter(Mandatory = $true)]
  [string]$WinresPath
)

$ErrorActionPreference = "Stop"

function Resolve-ExistingExecutablePath {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Value
  )

  $candidates = @()

  if ($Value -is [System.Array]) {
    $allParts = New-Object System.Collections.Generic.List[string]

    foreach ($item in $Value) {
      $part = [string]$item
      $candidates += $part
      [void]$allParts.Add($part)
    }

    if ($allParts.Count -gt 0) {
      $joined = [string]::Concat($allParts)
      if (-not [string]::IsNullOrWhiteSpace($joined)) {
        $candidates = @($joined) + $candidates
      }
    }
  } else {
    $candidates += [string]$Value
  }

  foreach ($candidate in $candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }

    $trimmed = $candidate.Trim()

    if (Test-Path -LiteralPath $trimmed) {
      return (Resolve-Path -LiteralPath $trimmed).Path
    }

    $match = [regex]::Match($trimmed, '([A-Za-z]:\\.*?\.exe)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($match.Success) {
      $possiblePath = $match.Groups[1].Value
      if (Test-Path -LiteralPath $possiblePath) {
        return (Resolve-Path -LiteralPath $possiblePath).Path
      }
    }
  }

  return $null
}

function Invoke-External {
  param(
    [Parameter(Mandatory = $true)]
    [object]$FilePath,
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $resolvedFilePath = Resolve-ExistingExecutablePath -Value $FilePath

  if ([string]::IsNullOrWhiteSpace($resolvedFilePath) -or !(Test-Path -LiteralPath $resolvedFilePath)) {
    $valueType = if ($null -eq $FilePath) { '<null>' } else { $FilePath.GetType().FullName }
    throw "Executable not found. Type=$valueType Raw='$FilePath'"
  }

  & $resolvedFilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $resolvedFilePath $($Arguments -join ' ')"
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

function Ensure-RcEdit {
  $toolsDir = Join-Path $PSScriptRoot ".tools"
  $rcEditPath = Join-Path $toolsDir "rcedit-x64.exe"

  if (Test-Path $rcEditPath) {
    return (Resolve-Path -LiteralPath $rcEditPath).Path
  }

  New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null

  $downloadUrl = "https://github.com/electron/rcedit/releases/download/v2.0.0/rcedit-x64.exe"
  Invoke-WebRequest -Uri $downloadUrl -OutFile $rcEditPath | Out-Null
  return (Resolve-Path -LiteralPath $rcEditPath).Path
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

$rcEdit = Ensure-RcEdit

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
