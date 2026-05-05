# Proxy Shim

A lightweight proxy executable built in Zig.

## Building

To build the proxy executable:

```powershell
.\build.ps1
```

This will create `bin/proxy.exe` in the main shim directory.

### Build Profiles

You can specify different build profiles:

```powershell
.\build.ps1 -BuildProfile Debug      # Debug build
.\build.ps1 -BuildProfile ReleaseFast # Optimized for speed
.\build.ps1 -BuildProfile ReleaseSafe # Optimized for safety
.\build.ps1 -BuildProfile ReleaseSmall # Optimized for size (default)
```

### Custom Output Path

You can specify a custom output location:

```powershell
.\build.ps1 -OutputExe "custom\path\proxy.exe"
```
