param(
	[Parameter(Mandatory = $true)]
	[string]$ExePath,
	[Parameter(Mandatory = $true)]
	[string]$WinresPath
)

$ErrorActionPreference = "Stop"

function Get-TrimmedString {
	param([object]$Value)

	if ($null -eq $Value) {
		return $null
	}

	$stringValue = [string]$Value
	if ([string]::IsNullOrWhiteSpace($stringValue)) {
		return $null
	}

	return $stringValue.Trim()
}

function Add-RcEditOption {
	param(
		[System.Collections.Generic.List[string]]$Arguments,
		[string]$Name,
		[string]$Value
	)

	$trimmed = Get-TrimmedString $Value
	if ($trimmed) {
		$Arguments.Add($Name)
		$Arguments.Add($trimmed)
	}

	return $Arguments
}

function Convert-ExecutionLevel {
	param([string]$Level)

	$normalized = (Get-TrimmedString $Level)
	if (-not $normalized) {
		return $null
	}

	$normalized = $normalized.ToLowerInvariant().Replace(" ", "")
	switch ($normalized) {
		"asinvoker" { return "asInvoker" }
		"highestavailable" { return "highestAvailable" }
		"requireadministrator" { return "requireAdministrator" }
		default { return $null }
	}
}

function New-ApplicationManifest {
	param(
		[pscustomobject]$ManifestBlock,
		[string]$DestinationDir
	)

	if ($null -eq $ManifestBlock) {
		return $null
	}

	$identityName = Get-TrimmedString $ManifestBlock.identity.name
	$identityVersion = Get-TrimmedString $ManifestBlock.identity.version
	$description = Get-TrimmedString $ManifestBlock.description
	$requestedExecutionLevel = Convert-ExecutionLevel $ManifestBlock.'execution-level'
	$uiAccess = if ($ManifestBlock.'ui-access') { "true" } else { "false" }
	$useCommonControls = [bool]$ManifestBlock.'use-common-controls-v6'

	if (-not $identityName -and -not $identityVersion -and -not $description -and -not $requestedExecutionLevel -and -not $useCommonControls) {
		return $null
	}

	$escapedIdentityName = if ($identityName) { [System.Security.SecurityElement]::Escape($identityName) } else { $null }
	$escapedIdentityVersion = if ($identityVersion) { [System.Security.SecurityElement]::Escape($identityVersion) } else { $null }
	$escapedDescription = if ($description) { [System.Security.SecurityElement]::Escape($description) } else { $null }

	$lines = New-Object System.Collections.Generic.List[string]
	$lines.Add('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
	$lines.Add('<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">')

	if ($escapedIdentityName -or $escapedIdentityVersion) {
		$identityAttributes = New-Object System.Collections.Generic.List[string]
		if ($escapedIdentityName) {
			$identityAttributes.Add("name=`"$escapedIdentityName`"")
		}
		if ($escapedIdentityVersion) {
			$identityAttributes.Add("version=`"$escapedIdentityVersion`"")
		}
		$lines.Add("  <assemblyIdentity $([string]::Join(' ', $identityAttributes)) />")
	}

	if ($escapedDescription) {
		$lines.Add("  <description>$escapedDescription</description>")
	}

	if ($requestedExecutionLevel) {
		$lines.Add('  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">')
		$lines.Add('    <security>')
		$lines.Add('      <requestedPrivileges>')
		$lines.Add("        <requestedExecutionLevel level=`"$requestedExecutionLevel`" uiAccess=`"$uiAccess`" />")
		$lines.Add('      </requestedPrivileges>')
		$lines.Add('    </security>')
		$lines.Add('  </trustInfo>')
	}

	if ($useCommonControls) {
		$lines.Add('  <dependency>')
		$lines.Add('    <dependentAssembly>')
		$lines.Add('      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />')
		$lines.Add('    </dependentAssembly>')
		$lines.Add('  </dependency>')
	}

	$lines.Add('</assembly>')

	$manifestPath = Join-Path $DestinationDir "app.manifest"
	[System.IO.File]::WriteAllLines($manifestPath, $lines, [System.Text.UTF8Encoding]::new($false))
	return $manifestPath
}

$resolvedExePath = [System.IO.Path]::GetFullPath($ExePath)
$resolvedWinresPath = [System.IO.Path]::GetFullPath($WinresPath)

if (!(Test-Path -LiteralPath $resolvedExePath -PathType Leaf)) {
	throw "target executable not found at $resolvedExePath"
}

if (!(Test-Path -LiteralPath $resolvedWinresPath -PathType Leaf)) {
	throw "winres definition not found at $resolvedWinresPath"
}

$goWinres = Get-Command go-winres -ErrorAction SilentlyContinue
if ($goWinres) {
	& $goWinres.Source patch --in $resolvedWinresPath --no-backup $resolvedExePath
	if ($LASTEXITCODE -ne 0) {
		throw "go-winres patch failed with exit code $LASTEXITCODE"
	}
	return
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$defaultRcEditPath = Join-Path $scriptRoot ".tools\rcedit-x64.exe"
$resolvedRcEditPath = $null

if ($env:RCEDIT_PATH -and (Test-Path -LiteralPath $env:RCEDIT_PATH -PathType Leaf)) {
	$resolvedRcEditPath = [System.IO.Path]::GetFullPath($env:RCEDIT_PATH)
} elseif (Test-Path -LiteralPath $defaultRcEditPath -PathType Leaf) {
	$resolvedRcEditPath = [System.IO.Path]::GetFullPath($defaultRcEditPath)
}

if (-not $resolvedRcEditPath) {
	throw "neither go-winres nor rcedit is available; install go-winres or set RCEDIT_PATH"
}

$winres = Get-Content -LiteralPath $resolvedWinresPath -Raw | ConvertFrom-Json
$versionBlock = $winres.RT_VERSION.'#1'.'0000'
$versionInfo = $versionBlock.info.'0409'
$manifestBlock = $winres.RT_MANIFEST.'#1'.'0409'
$iconRef = Get-TrimmedString $winres.RT_GROUP_ICON.'#1'.'0000'
$requestedExecutionLevel = Convert-ExecutionLevel $manifestBlock.'execution-level'
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString("N"))

New-Item -ItemType Directory -Path $workDir -Force | Out-Null
try {
	$rcEditArgs = New-Object System.Collections.Generic.List[string]
	$rcEditArgs.Add($resolvedExePath)

	if ($iconRef) {
		$iconPath = if ([System.IO.Path]::IsPathRooted($iconRef)) {
			[System.IO.Path]::GetFullPath($iconRef)
		} else {
			[System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $resolvedWinresPath) $iconRef))
		}

		if (Test-Path -LiteralPath $iconPath -PathType Leaf) {
			$rcEditArgs = Add-RcEditOption -Arguments $rcEditArgs -Name "--set-icon" -Value $iconPath
		}
	}

	$rcEditArgs = Add-RcEditOption -Arguments $rcEditArgs -Name "--set-file-version" -Value (Get-TrimmedString $versionBlock.fixed.file_version)
	$rcEditArgs = Add-RcEditOption -Arguments $rcEditArgs -Name "--set-product-version" -Value (Get-TrimmedString $versionBlock.fixed.product_version)

	if ($versionInfo) {
		foreach ($property in $versionInfo.PSObject.Properties) {
			$value = Get-TrimmedString $property.Value
			if (-not $value) {
				continue
			}

			$rcEditArgs.Add("--set-version-string")
			$rcEditArgs.Add($property.Name)
			$rcEditArgs.Add($value)
		}
	}

	if ($requestedExecutionLevel) {
		$rcEditArgs = Add-RcEditOption -Arguments $rcEditArgs -Name "--set-requested-execution-level" -Value $requestedExecutionLevel
	}

	$manifestPath = New-ApplicationManifest -ManifestBlock $manifestBlock -DestinationDir $workDir
	if ($manifestPath) {
		$rcEditArgs = Add-RcEditOption -Arguments $rcEditArgs -Name "--application-manifest" -Value $manifestPath
	}

	& $resolvedRcEditPath @rcEditArgs
	if ($LASTEXITCODE -ne 0) {
		throw "rcedit failed with exit code $LASTEXITCODE"
	}
}
finally {
	if (Test-Path -LiteralPath $workDir) {
		Remove-Item -LiteralPath $workDir -Recurse -Force
	}
}