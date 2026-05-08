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

$statuses = New-Object System.Collections.Generic.List[object]

function Add-Status {
	param(
		[string]$Component,
		[string]$Status,
		[string]$OutputPath,
		[double]$Seconds
	)

	$size = ""
	if ($Status -eq "OK" -and (Test-Path $OutputPath)) {
		$bytes = (Get-Item $OutputPath).Length
		$size = if ($bytes -ge 1MB) { "$([Math]::Round($bytes / 1MB, 2)) MB" } else { "$([Math]::Round($bytes / 1KB, 1)) KB" }
	}

	$statuses.Add([PSCustomObject]@{
		Component = $Component
		Status    = $Status
		Seconds   = [Math]::Round($Seconds, 2)
		Size      = $size
		Output    = $OutputPath
	})
}

function Invoke-ComponentBuild {
	param(
		[string]$Component,
		[string]$OutputExe,
		[scriptblock]$Action
	)

	Write-Host "`n[$Component] Building..."
	$sw = [System.Diagnostics.Stopwatch]::StartNew()
	try {
		& $Action
		if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
			throw "Build exited with code $LASTEXITCODE"
		}
		$sw.Stop()
		Add-Status -Component $Component -Status "OK" -OutputPath $OutputExe -Seconds $sw.Elapsed.TotalSeconds
		Write-Host "[$Component] OK"
	}
	catch {
		$sw.Stop()
		Add-Status -Component $Component -Status "FAILED" -OutputPath $OutputExe -Seconds $sw.Elapsed.TotalSeconds
		Write-Host "[$Component] FAILED: $($_.Exception.Message)" -ForegroundColor Red
		throw
	}
}

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

$nodeExe   = Join-Path $outputDir ".shim\node.exe"
$reshimExe = Join-Path $binDir "reshim.exe"
$proxyExe  = Join-Path $binDir "proxy.exe"

$failed = $false

try {
	Invoke-ComponentBuild -Component "node" -OutputExe $nodeExe -Action {
		& "$scriptRoot\node\build.ps1" -OutputExe $nodeExe @commonArgs
	}
} catch { $failed = $true }

try {
	Invoke-ComponentBuild -Component "reshim" -OutputExe $reshimExe -Action {
		& "$scriptRoot\reshim\build.ps1" -OutputExe $reshimExe @commonArgs
	}
} catch { $failed = $true }

try {
	Invoke-ComponentBuild -Component "proxy" -OutputExe $proxyExe -Action {
		& "$scriptRoot\proxy\build.ps1" -OutputExe $proxyExe @commonArgs
	}
} catch { $failed = $true }

Write-Host "`nBuild Summary"
Write-Host "============="
$statuses | Format-Table -AutoSize Component, Status, Seconds, Size, Output

if ($failed) {
	$failedComponents = @($statuses | Where-Object { $_.Status -eq "FAILED" } | Select-Object -ExpandProperty Component)
	Write-Host "Overall Status: FAILED ($([string]::Join(', ', $failedComponents)))" -ForegroundColor Red
	exit 1
}

Write-Host "Overall Status: OK" -ForegroundColor Green
