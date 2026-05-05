# NVM for Windows Shim

Introduced in NVM for Windows v2.0.0, the shim adds another option for running different versions of Node.js dynamically.

Historically, NVM for Windows only supported symlinks. Symlinks and shims each have tradeoffs. You can learn more about these tradeoffs and which mode is best for you on [docs.nvm-windows.com](https://docs.nvm-windows.com).

## Version Detection

The shim supports nvm-window's automatic version detection capabilities. Users can configure their own detection files, but nvm-windows defaults to `.nvmrc`, `.node-version`, and `package.json`.

> [!TIP]
> Use `--nvm-use-which` to identify how the version is sourced (i.e. which file or preference).

> [!NOTE]
> Automatic version detection can be disabled.

## Version Overrides

Add `--nvm-use <version>` to any node command to use a different version for a single invocation. This can be useful when testing an app against newer/older versions of Node.js without changing the base version.

```sh
node myfile.js # run normally
node --nvm-use 22 myfile.js # run ONCE with Node.js 22
```

## Auto-installation

If a detected version is not installed, nvm-windows can install it automatically.

> [!NOTE]
> Auto-installation can be configured to prompt before install or turned off entirely.

## Performance

Written in Zig, the shim adds 0-3ms overhead (avg 15-25% faster than Rust).

The Windows operating system uses [`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) to launch _any executable_, no matter which language it is written in. This unavoidable "universal latency tax" typically adds 10-30ms, which is still hard to notice for most people.

NVM for Windows historically bypassed this using symlinks, which have zero perceptable latency. Symlinks and shims offer different advna

> [!TIP]
> NVM for Windows link mode offers a zero latency option, with minor limitations.

---

Copyright &copy; 2026, Author Software Inc. All rights reserved.
