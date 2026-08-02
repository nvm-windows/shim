# shim

This repo contains the shims used in NVM for Windows' "shim" operating mode. For details about using shim mode, see the [official documentation](https://docs.nvm-windows.com).

This repo contains several required executables for full Node.js verison management.

- `nvm.exe` ([cli](https://github.com/nvm-windows/cli)) is responsible for downloads, (un)installs, caching, and configuration.
- `node.exe` ([node/README.md](node/README.md)) is the shim used to run Node.js, including shim-only flags such as `--nvm-use` and `--nvm-which`.
- `proxy.exe` (this repo) is the global module shim (npm, npx, custom).
- `reshim.exe` (this repo) is a helper utility for syncing shims.
- `sync.exe` (private) is a closed source add-on app for identifying updates, releases, and fixes.

# Building from Source

This application uses a custom build.zig file shared across the shim directories, plus `build.zig.zon` (package identity; **no remote product deps** — first-party modules + Zig std + Windows system libs). Build-tool dep: [zig-build-sbom](https://github.com/OrlovEvgeny/zig-build-sbom) for CycloneDX (`zig build sbom`; see `scripts/Export-ZigBuildSbom.ps1`).

**Build All**

```powershell
.\build.ps1 -Architecture amd64/arm64
```

**Export shim SBOM (CycloneDX)**

```powershell
.\scripts\Export-ZigBuildSbom.ps1 -App node -OutputPath .\node.cdx.json -Version 2.0.0-alpha.1
```

**Build Node Shim**

```powershell
cd node
.\build.ps1
```

**Build Proxy Shim**

```powershell
cd proxy
.\build.ps1
```

**Build Reshim App**

```powershell
cd reshim
.\build.ps1
```
