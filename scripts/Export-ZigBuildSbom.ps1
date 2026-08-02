param(
	[Parameter(Mandatory = $true)]
	[ValidateSet("node", "proxy", "reshim")]
	[string]$App,

	[Parameter(Mandatory = $true)]
	[string]$OutputPath,

	[string]$Version = "0.0.0-dev",
	[ValidateSet("ReleaseSmall", "ReleaseSafe", "ReleaseFast", "Debug")]
	[string]$BuildProfile = "ReleaseSmall",
	[ValidateSet("amd64", "arm64")]
	[string]$Architecture = "amd64",
	[string]$RegistryPath = "",
	[string]$CacheDir = "",
	[string]$ShimRoot = ""
)

# Exports CycloneDX via zig-build-sbom (`zig build sbom`).
# Works around zig-build-sbom 0.1.0 Windows bug: source_url filled with 0xAA
# (undefined) bytes → serializer SyntaxError.
# Upstream: https://github.com/OrlovEvgeny/zig-build-sbom/issues/1
# (UAF: dep URL map freed while Component.source_url still aliases it.)
# Sanitizes intermediate JSON, re-runs sbom-serializer, strips build-tool packages.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($ShimRoot)) {
	$ShimRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
}
$ShimRoot = [System.IO.Path]::GetFullPath($ShimRoot)
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

if ([string]::IsNullOrWhiteSpace($CacheDir)) {
	$CacheDir = Join-Path $env:LOCALAPPDATA "nvm-windows\zig-cache"
}
New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null

$target = if ($Architecture -eq "arm64") { "aarch64-windows-msvc" } else { "x86_64-windows-msvc" }
$zigArgs = @(
	"build", "sbom",
	"--build-file", (Join-Path $ShimRoot "build.zig"),
	"--cache-dir", $CacheDir,
	"-Dapp=$App",
	"-Dtarget=$target",
	"-Doptimize=$BuildProfile",
	"-Dversion=$Version"
)
if (-not [string]::IsNullOrWhiteSpace($RegistryPath)) {
	$regFull = [System.IO.Path]::GetFullPath($RegistryPath)
	$regRel = [System.IO.Path]::GetRelativePath($ShimRoot, $regFull).Replace('\', '/')
	$zigArgs += "-Dregistry_path=$regRel"
}

function Test-HasProperty {
	param(
		[Parameter(Mandatory = $true)]$Object,
		[Parameter(Mandatory = $true)][string]$Name
	)
	return $null -ne ($Object.PSObject.Properties.Name | Where-Object { $_ -eq $Name })
}

function Repair-SbomIntermediateJson {
	param([Parameter(Mandatory = $true)][string]$Path)

	$bytes = [System.IO.File]::ReadAllBytes($Path)
	for ($i = 0; $i -lt $bytes.Length; $i++) {
		if ($bytes[$i] -eq 0xAA) {
			$bytes[$i] = [byte][char]'X'
		}
	}
	$text = [System.Text.Encoding]::UTF8.GetString($bytes)
	# Collapse corrupted source_url strings to null.
	$text = [regex]::Replace($text, '"source_url"\s*:\s*"X+"', '"source_url":null')
	$utf8 = New-Object System.Text.UTF8Encoding $false
	[System.IO.File]::WriteAllText($Path, $text, $utf8)
}

function Remove-BuildToolComponents {
	param([Parameter(Mandatory = $true)][string]$CdxPath)

	$bom = Get-Content -LiteralPath $CdxPath -Raw -Encoding UTF8 | ConvertFrom-Json
	$drop = @("zig_build_sbom", "serde", "zig-build-sbom")
	$keep = New-Object System.Collections.Generic.List[object]
	$dropRefs = New-Object 'System.Collections.Generic.HashSet[string]'

	foreach ($c in @($bom.components)) {
		$name = [string]$c.name
		$ref = ""
		if (Test-HasProperty -Object $c -Name "bom-ref") {
			$ref = [string]$c."bom-ref"
		}
		if ($drop -contains $name) {
			if (-not [string]::IsNullOrWhiteSpace($ref)) {
				[void]$dropRefs.Add($ref)
			}
			continue
		}
		[void]$keep.Add($c)
	}
	$bom.components = @($keep.ToArray())

	if ($null -ne $bom.dependencies) {
		$depOut = New-Object System.Collections.Generic.List[object]
		foreach ($d in @($bom.dependencies)) {
			$ref = [string]$d.ref
			if ($dropRefs.Contains($ref)) { continue }
			$rawDepends = @()
			if ($null -ne $d.dependsOn) { $rawDepends = @($d.dependsOn) }
			$depends = @(
				$rawDepends |
					ForEach-Object { [string]$_ } |
					Where-Object { -not $dropRefs.Contains($_) }
			)
			[void]$depOut.Add([pscustomobject]@{
					ref       = $ref
					dependsOn = @($depends)
				})
		}
		$bom.dependencies = @($depOut.ToArray())
	}

	# Root is an application EXE, not firmware.
	if ($null -ne $bom.metadata -and $null -ne $bom.metadata.component) {
		$bom.metadata.component.type = "application"
		if ([string]$bom.metadata.component.name -eq "nvm_windows_shim") {
			$bom.metadata.component.name = $App
			if (Test-HasProperty -Object $bom.metadata.component -Name "bom-ref") {
				$bom.metadata.component."bom-ref" = $App
			}
		}
	}

	$json = $bom | ConvertTo-Json -Depth 40
	$utf8 = New-Object System.Text.UTF8Encoding $false
	[System.IO.File]::WriteAllText($CdxPath, $json, $utf8)
}

function Resolve-SbomIntermediatePath {
	$candidates = @(
		(Join-Path $CacheDir "sbom_intermediate_$App.json"),
		(Join-Path $ShimRoot ".zig-cache\sbom_intermediate_$App.json")
	)
	foreach ($p in $candidates) {
		if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
	}
	return $null
}

Write-Host "zig-build-sbom export -> app=$App output=$OutputPath"

Push-Location $ShimRoot
try {
	$zigExe = (Get-Command zig -ErrorAction Stop).Source
	# On Windows, zig-build-sbom 0.1.0 often fails serializer (bad source_url);
	# intermediate JSON is still written. Capture noise; sanitize path below.
	$zigOut = & $zigExe @zigArgs 2>&1
	$zigExit = if (Test-Path variable:LASTEXITCODE) { $LASTEXITCODE } else { 0 }
	if ($zigExit -eq 0) {
		$zigOut | ForEach-Object { Write-Host "$_" }
	}
	else {
		Write-Host "zig build sbom exit $zigExit (expected on Windows until upstream source_url fix); sanitizing intermediate..." -ForegroundColor Yellow
	}
}
finally {
	Pop-Location
}

$produced = $null
if ($zigExit -eq 0) {
	$candidates = @(
		Get-ChildItem -LiteralPath $CacheDir -Recurse -Filter "$App.cdx.json" -ErrorAction SilentlyContinue
		Get-ChildItem -LiteralPath (Join-Path $ShimRoot ".zig-cache") -Recurse -Filter "$App.cdx.json" -ErrorAction SilentlyContinue
	) | Where-Object { $null -ne $_ } | Select-Object -ExpandProperty FullName -Unique
	if (@($candidates).Count -gt 0) {
		$produced = $candidates[0]
	}
}

if ([string]::IsNullOrWhiteSpace($produced)) {
	$intermediate = Resolve-SbomIntermediatePath
	if ([string]::IsNullOrWhiteSpace($intermediate)) {
		throw "zig-build-sbom intermediate JSON missing after build (exit $zigExit): looked for sbom_intermediate_$App.json"
	}

	Write-Host "Sanitizing intermediate SBOM JSON (zig-build-sbom Windows source_url bug) -> $intermediate" -ForegroundColor Yellow
	Repair-SbomIntermediateJson -Path $intermediate

	$serializer = @(
		Get-ChildItem -LiteralPath $CacheDir -Recurse -Filter "sbom-serializer.exe" -ErrorAction SilentlyContinue
		Get-ChildItem -LiteralPath (Join-Path $ShimRoot ".zig-cache") -Recurse -Filter "sbom-serializer.exe" -ErrorAction SilentlyContinue
	) | Select-Object -First 1
	if ($null -eq $serializer) {
		throw "sbom-serializer.exe not found under Zig cache (build sbom once to compile it)."
	}

	$tmpOut = Join-Path $env:TEMP ("zig-sbom-{0}-{1}.cdx.json" -f $App, [guid]::NewGuid().ToString("N"))
	Write-Host "Running $($serializer.FullName)"
	& $serializer.FullName $intermediate $tmpOut "cyclonedx-json"
	$serExit = if (Test-Path variable:LASTEXITCODE) { $LASTEXITCODE } else { 0 }
	if ($serExit -ne 0) {
		throw "sbom-serializer failed with exit code $serExit"
	}
	if (-not (Test-Path -LiteralPath $tmpOut -PathType Leaf)) {
		throw "sbom-serializer did not write $tmpOut"
	}
	$produced = $tmpOut
}

Copy-Item -LiteralPath $produced -Destination $OutputPath -Force
Remove-BuildToolComponents -CdxPath $OutputPath
Write-Host "Zig SBOM ready -> $OutputPath"
return $OutputPath
