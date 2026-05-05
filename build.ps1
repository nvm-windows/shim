param(
	[string]$OutputDir = "..\bin",
	[ValidateSet("ReleaseSmall", "ReleaseSafe", "ReleaseFast", "Debug")]
	[string]$BuildProfile = "ReleaseSmall",
	[string]$Version,
	[string]$RegistryOverride,
	[ValidateSet("amd64", "arm64")]
	[string]$Architecture
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputDir = if ([System.IO.Path]::IsPathRooted($OutputDir)) {
	[System.IO.Path]::GetFullPath($OutputDir)
} else {
	[System.IO.Path]::GetFullPath((Join-Path $scriptRoot $OutputDir))
}
$binDir = Join-Path $outputDir "utils"
$repoLocalZigCacheDir = Join-Path $scriptRoot ".zig-cache"

Write-Host "Building all shims -> $outputDir"

if (Test-Path $repoLocalZigCacheDir) {
	try {
		Remove-Item $repoLocalZigCacheDir -Recurse -Force
		Write-Host "Removed stale local Zig cache at $repoLocalZigCacheDir"
	}
	catch {
		Write-Warning "Unable to remove stale local Zig cache at ${repoLocalZigCacheDir}: $($_.Exception.Message)"
	}
}

$commonArgs = @{ BuildProfile = $BuildProfile }
if ($Version) {
	$commonArgs.Version = $Version
}
if ($RegistryOverride) {
	$commonArgs.RegistryOverride = $RegistryOverride
}
if ($Architecture) {
	$commonArgs.Architecture = $Architecture
}

& "$scriptRoot\node\build.ps1" -OutputExe (Join-Path $outputDir ".shim\node.exe") @commonArgs
& "$scriptRoot\reshim\build.ps1" -OutputExe (Join-Path $binDir "reshim.exe") @commonArgs
& "$scriptRoot\proxy\build.ps1" -OutputExe (Join-Path $binDir "proxy.exe") @commonArgs

Write-Host "Done."
