# NVM for Windows Shim

Introduced in NVM for Windows v2.0.0, the shim adds another option for running different versions of Node.js dynamically.

Historically, NVM for Windows only supported symlinks. Symlinks and shims each have tradeoffs. You can learn more about these tradeoffs and which mode is best for you on [docs.nvm-windows.com](https://docs.nvm-windows.com).

## Version Detection

The shim supports NVM for Windows automatic version detection. Users can configure their own detection files, but nvm-windows defaults to `.nvmrc`, `.node-version`, and `package.json`.

> [!TIP]
> Add `--nvm-which` to any `node` or proxy command to print how the version was resolved (registry preference, detection file, alias, etc.) before the command runs.

```sh
node --version --nvm-which
npm --nvm-which --version
```

Example output:

```text
nvm version resolution: source=preference requested= effective=24.16.0 resolved=24.16.0 node=C:\Users\...\node.exe
v24.16.0
```

> [!NOTE]
> Automatic version detection can be disabled.

## Shim flags

These flags are parsed by the shim and are not passed to Node.js or package managers. They may appear anywhere in the command line.

| Flag | Purpose |
|------|---------|
| `--nvm-use <version>` | Run once with a specific Node.js version |
| `--nvm-use=<version>` | Same as `--nvm-use <version>` |
| `--nvm-which` | Print version resolution details |
| `--nvm-shim-version` | Print the shim executable version |

## Version Overrides

Add `--nvm-use <version>` to any node command to use a different version for a single invocation. This can be useful when testing an app against newer/older versions of Node.js without changing the base version.

```sh
node myfile.js # run normally
node --nvm-use 22 myfile.js # run ONCE with Node.js 22
node --nvm-use=22 myfile.js # same as above
```

## Auto-installation

If a detected version is not installed, nvm-windows can install it automatically.

> [!NOTE]
> Auto-installation can be configured to prompt before install or turned off entirely.

## Performance

Written in Zig, the shim adds 0-3ms overhead for version resolution (avg 15-25% faster than Rust).

In shim mode, NVM for Windows also verifies the resolved `node.exe` before spawn. A **verify cache** (public key in `{DataRoot}/.verify/`, signed entries in HKCU) keeps that check to ~1–2 ms on cache hits. If the cache or public key is missing, the shim falls back to full Authenticode verification (slower, still secure). See [Runtime Verify Cache](https://docs.nvm-windows.com/guide/verify-cache) and `nvm doctor`.

The Windows operating system uses [`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) to launch _any executable_, no matter which language it is written in. This unavoidable "universal latency tax" typically adds 10-30ms, which is still hard to notice for most people.

NVM for Windows historically bypassed this using symlinks, which have zero perceptible latency. Symlinks and shims offer different advantages.

> [!TIP]
> NVM for Windows link mode offers a zero latency option, with minor limitations.

---

Copyright &copy; 2026, Author Software Inc. All rights reserved.
