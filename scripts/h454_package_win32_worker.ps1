# H454: package source-pinned Python native Win32 READ worker.
# GitHub-hosted Windows CI ONLY. Never install, sign or distribute this EXE.
param(
    [Parameter(Mandatory=$true)][string]$ExpectedSha,
    [Parameter(Mandatory=$true)][string]$Destination
)
$ErrorActionPreference = 'Stop'
try {
    if ($env:RUNNER_OS -ne 'Windows' -or
        $ExpectedSha -cnotmatch '^[a-f0-9]{40}$' -or
        -not $env:RUNNER_TEMP -or -not $env:GITHUB_WORKSPACE) {
        throw 'H454_WIN32_WORKER_BUILD_HOLD_INPUT'
    }
    $actual = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -cne $ExpectedSha) {
        throw 'H454_WIN32_WORKER_BUILD_HOLD_SHA'
    }
    $temp = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    $dest = [IO.Path]::GetFullPath($Destination)
    if (-not $dest.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $dest) -or
        (Test-Path -LiteralPath (Join-Path $env:RUNNER_TEMP 'h454-win32-pyinstaller'))) {
        throw 'H454_WIN32_WORKER_BUILD_HOLD_SCOPE'
    }
    $work = Join-Path $env:RUNNER_TEMP 'h454-win32-pyinstaller'
    $spec = Join-Path $work 'spec'
    $interim = Join-Path $work 'work'
    New-Item -ItemType Directory -Path $dest, $spec, $interim -Force | Out-Null
    # Build-only dependencies. Exact versions and no runtime credentials.
    python -m pip install --disable-pip-version-check --no-cache-dir --no-input 'pyinstaller==6.22.3' 'websockets==17.2'
    if ($LASTEXITCODE -ne 0) { throw 'H454_WIN32_WORKER_BUILD_HOLD_DEPENDENCY' }
    python -c "import PyInstaller, websockets; assert PyInstaller.__version__ == '6.22.3' and websockets.__version__ == '17.2'"
    if ($LASTEXITCODE -ne 0) { throw 'H454_WIN32_WORKER_BUILD_HOLD_DEPENDENCY_VERSION' }
    python -m PyInstaller --onefile --clean --noconfirm --console --paths $env:GITHUB_WORKSPACE --hidden-import websockets.sync.client --distpath $dest --workpath $interim --specpath $spec --name HermesCommanderNativeWorker scripts/h454_native_win32_worker.py
    if ($LASTEXITCODE -ne 0) { throw 'H454_WIN32_WORKER_BUILD_HOLD_PYINSTALLER' }
    $binary = Join-Path $dest 'HermesCommanderNativeWorker.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf) -or
        (Get-AuthenticodeSignature -LiteralPath $binary).Status.ToString() -ne 'NotSigned') {
        throw 'H454_WIN32_WORKER_BUILD_HOLD_SIGNATURE'
    }
    # Hosted runner is NOT NT SERVICE\HermesCommanderNative: refuse before
    # touching any original project, owner BRC relay or DPAPI state.
    $run = Start-Process -FilePath $binary -ArgumentList @(
        '--run-once', '--release-sha', $ExpectedSha
    ) -Wait -PassThru -NoNewWindow
    if ($run.ExitCode -ne 2) {
        throw 'H454_WIN32_WORKER_BUILD_HOLD_WRONG_SID_NOT_DENIED'
    }
    Write-Output 'H454_WIN32_WORKER_PACKAGED_SYNTHETIC=PASS'
    Write-Output 'H454_OWNER_WINDOWS_ORIGINAL_HOST=NOT_RUN'
} catch {
    Write-Error 'H454_WIN32_WORKER_BUILD=HOLD' -ErrorAction Continue
    exit 2
}
