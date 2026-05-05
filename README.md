# shim

This repo contains the shims used in NVM for Windows' "shim" operating mode. For details about using shim mode, see the [official documentation](https://docs.nvm-windows.com).

This repo contains several required executables for full Node.js verison management.

- `nvm.exe` ([nvm](https://github.com/nvm-windows/nvm)) is responsible for downloads, (un)installs, caching, and configuration.
- `node.exe` (this repo) is the shim used to run Node.js.
- `proxy.exe` (this repo) is the global module shim (npm, npx, custom).
- `reshim.exe` (this repo) is a helper utility for syncing shims.
- `sync.exe` (private) is a closed source add-on app for identifying updates, releases, and fixes.

# Building from Source

This application uses a custom build.zig file shared across the shim directories.

**Build All**

```powershell
.\build.ps1 -Architecture amd64/arm64
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