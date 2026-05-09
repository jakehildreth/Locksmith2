# ADR-0002: Promote PS5.1 to First-Class Runtime; Remove PwshSpectreConsole, Windows Terminal, and PS7.4+ Checks

## Status

Accepted

## Context

The original design of Locksmith2 treated Windows PowerShell 5.1 as a second-class,
headless-only runtime. The intended TUI experience required:

- **PowerShell 7.4+** — `PwshSpectreConsole` only supports PS7+.
- **Windows Terminal** — assumed to be the host for VT100/ANSI rendering.
- **PwshSpectreConsole** — the third-party module providing all interactive UI widgets
  (progress bars, tables, prompts, color theming).

As a result, the first-run experience (`Test-PowerShellEnvironment` +
`Repair-PowerShellEnvironment`) emitted warnings when these conditions were not met:

```
Windows PowerShell detected. Locksmith 2 will run in headless mode.
Interactive mode requires PowerShell 7.4+.

Locksmith 2 is designed to work on Windows Terminal. Visual output may
be degraded.

Needed module 'PwshSpectreConsole' is not loaded. Locksmith 2 will
guide you through installation and importation.
```

This design had two practical problems:

1. **PS5.1 is the dominant installed version in enterprise environments.** Domain-joined
   Windows machines ship with PS5.1. Many administrators have never installed PS7 and
   have no path to do so without IT involvement. Locking the full TUI experience behind
   PS7.4+ made Locksmith2 hostile to the majority of its target audience.

2. **PwshSpectreConsole added fragility.** It is a large, opinionated dependency that
   introduces its own upgrade surface, breaking changes, and install friction. Requiring
   users to install it — and then gating the experience behind that install — was a poor
   first-run experience on any PS version.

Investigation revealed that PS5.1 conhost *does* support VT100/ANSI escape sequences,
but virtual terminal processing must be enabled explicitly on the stdout handle via
`SetConsoleMode` before escape codes are interpreted correctly. The garbled logo output
observed in PS5.1 (`â–ˆ` instead of `█`) was not an encoding issue but a missing
`ENABLE_VIRTUAL_TERMINAL_PROCESSING` flag. Windows Terminal sets this flag automatically;
conhost does not.

`Show-Logo.ps1` was rewritten to enable VT processing natively via P/Invoke before
drawing, making it work correctly in both conhost and Windows Terminal under PS5.1 and
PS7+. This demonstrated that a full, pixel-art-quality TUI is achievable on PS5.1
without any third-party module.

## Decision

Promote PS5.1 to a full first-class runtime on equal footing with PS7.4+. The TUI will
be implemented entirely in native PowerShell using VT100/ANSI escape sequences with
explicit `SetConsoleMode` initialization. No third-party TUI module will be required.

As a consequence, the following checks are removed from `Test-PowerShellEnvironment`
and `Repair-PowerShellEnvironment`:

- **PowerShell 7.4+ check** — no longer warn PS5.1 users of degraded/headless mode.
- **Windows Terminal check** — `Test-IsWindowsTerminal` / `$testIsWindowsTerminal` removed
  from the environment check pipeline. VT processing is now enabled programmatically.
- **PwshSpectreConsole module check** — removed from `$neededModules` in
  `Test-PowerShellEnvironment` and from `Install-NeededModule` call sites.

`Test-IsWindowsTerminal.ps1` and `Test-IsPowerShellCore.ps1` are retained as utility
functions (they may be useful to callers) but are no longer invoked by the health-check
pipeline.

The `$returnObject` returned by `Test-PowerShellEnvironment` no longer includes
`IsPowerShellCore` or `IsWindowsTerminal` keys, since neither is actionable.

The PRD's "Headless Mode" section is superseded: PS5.1 now runs the same TUI as PS7+.
The distinction between Full Version and Headless Version in the original pseudocode is
eliminated.

## Consequences

[+] PS5.1 users get the full Locksmith2 TUI experience out of the box, with no warnings
    or second-class messaging.
[+] Eliminates PwshSpectreConsole as an install-time dependency entirely.
[+] Reduces first-run friction for all users — no module install prompts for optional UI.
[+] `Test-PowerShellEnvironment` return object is smaller and contains only actionable results.
[!] `IsPowerShellCore` and `IsWindowsTerminal` are no longer returned by
    `Test-PowerShellEnvironment`. Any caller relying on those keys must be updated.
[!] Future UI widgets (progress bars, tables, prompts) must be implemented in native
    PowerShell VT rather than delegated to PwshSpectreConsole.
[!] NerdFont detection/recommendation (previously TODO) is not added here; still deferred.

## Test Impact

The following test changes are required:

1. **`Test-PowerShellEnvironment.Tests.ps1`**
   - Remove `It 'should contain IsPowerShellCore key'`
   - Remove `It 'should contain IsWindowsTerminal key'`
   - Remove `It 'should return IsPowerShellCore as $true ...'`
   - Remove `It 'should return IsWindowsTerminal as $true ...'`
   - Remove `It 'should check for PwshSpectreConsole module'`
   - Mock for `Test-IsWindowsTerminal` and `Test-IsPowerShellCore` in `BeforeEach`
     can be removed.

2. **`Test-EnvironmentDetection.Tests.ps1`**
   - `Describe 'Test-IsWindowsTerminal'` and `Describe 'Test-IsPowerShellCore'` tests
     remain valid as unit coverage for the standalone functions but are no longer
     exercised by the health-check path. No removal required.

3. **`Repair-PowerShellEnvironment.Tests.ps1`**
   - Any test that supplies `IsWindowsTerminal` or `IsPowerShellCore` in the
     `$EnvironmentTest` hashtable parameter can drop those keys.

4. **`Install-NeededModule.Tests.ps1`** — no changes required; tests use generic
   module names and do not reference PwshSpectreConsole specifically.
