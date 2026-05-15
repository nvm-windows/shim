param(
	[string]$OutputExe = "..\bin\.shim\node.exe",
	[ValidateSet("ReleaseSmall", "ReleaseSafe", "ReleaseFast", "Debug")]
	[string]$BuildProfile = "ReleaseSmall",
	[string]$Version,
	[switch]$SyncSiblingNvm4w,
	[string]$SiblingNvm4wExe = "..\..\author\nvm4w\bin\.shim\node.exe",
	[string]$RegistryOverride,
	[ValidateSet("amd64", "arm64")]
	[string]$Architecture
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Architecture)) {
	if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64) {
		$Architecture = "arm64"
	} else {
		$Architecture = "amd64"
	}
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$shimRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot ".."))
$outputPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($scriptRoot, $OutputExe))
$outputDir = Split-Path -Parent $outputPath
$siblingOutputPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($scriptRoot, $SiblingNvm4wExe))
$siblingOutputDir = Split-Path -Parent $siblingOutputPath
$localCacheDir = Join-Path $env:LOCALAPPDATA "nvm-windows\zig-cache"
$localPrefixDir = Join-Path $env:LOCALAPPDATA "nvm-windows\zig-prefix\node"

if (-not $Version) {
	$winresPath = Join-Path $scriptRoot "winres\winres.json"
	if (Test-Path $winresPath) {
		$winres = Get-Content $winresPath -Raw | ConvertFrom-Json
		$versionFromInfo = $winres.RT_VERSION.'#1'.'0000'.info.'0409'.FileVersion
		if ($versionFromInfo) {
			$Version = [string]$versionFromInfo
		}
	}
}

if (!(Test-Path $localCacheDir)) {
	New-Item -ItemType Directory -Path $localCacheDir -Force | Out-Null
}

if (!(Test-Path $localPrefixDir)) {
	New-Item -ItemType Directory -Path $localPrefixDir -Force | Out-Null
}

if (!(Test-Path $outputDir)) {
	New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$zigArgs = @(
	"build",
	"--build-file", "$shimRoot\build.zig",
	"--cache-dir", $localCacheDir,
	"--prefix", $localPrefixDir,
	"-Dapp=node",
	"-Dtarget=$(if ($Architecture -eq 'arm64') { 'aarch64-windows-msvc' } else { 'x86_64-windows-msvc' })",
	"-Doptimize=$BuildProfile"
)

if ($Version) {
	$zigArgs += "-Dversion=$Version"
}

if ($RegistryOverride) {
	if (!(Test-Path $RegistryOverride)) {
		Write-Error "registry override not found at $RegistryOverride"
	}

	$registryOverridePath = [System.IO.Path]::GetFullPath($RegistryOverride)
	$zigArgs += "-Dregistry_path=$registryOverridePath"
}

Push-Location $scriptRoot
try {
	$zigExe = (Get-Command zig -ErrorAction Stop).Source
	if (!(Test-Path -LiteralPath $zigExe)) {
		throw "zig executable not found at $zigExe"
	}

	# Uses build.zig module imports to load shared registry/config without file staging.
	Push-Location $shimRoot
	try {
		& $zigExe @zigArgs

		if ($LASTEXITCODE -ne 0) {
			if ($BuildProfile -ne "Debug") {
				Write-Warning "zig build failed with profile '$BuildProfile'. Retrying with Debug profile to work around potential AV heuristic blocks."
				$retryArgs = @($zigArgs | Where-Object { $_ -notlike "-Doptimize=*" })
				$retryArgs += "-Doptimize=Debug"
				& $zigExe @retryArgs
			}

			if ($LASTEXITCODE -ne 0) {
				throw "zig build failed with exit code $LASTEXITCODE"
			}
		}
	}
	finally {
		Pop-Location
	}

	Copy-Item -Force (Join-Path $localPrefixDir "bin\node.exe") $outputPath
	& "$shimRoot\scripts\apply-winres.ps1" -ExePath $outputPath -WinresPath (Join-Path $scriptRoot "winres\winres.json")

	if ($SyncSiblingNvm4w) {
		if (!(Test-Path $siblingOutputDir)) {
			New-Item -ItemType Directory -Path $siblingOutputDir -Force | Out-Null
		}

		Copy-Item -Force $outputPath $siblingOutputPath
	}
}
finally {
	Pop-Location
}