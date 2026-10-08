# Install or update Consensus. No preinstalled Python, Git or administrator access needed.
# Release assets are published together by publish.yml.
# Keep shell preferences and script variables local when piped to Invoke-Expression.
param([string]$BundlePath, [string]$ConfigDirectory, [string]$ReportsDirectory,
      [switch]$OfferLaunch, [switch]$NoShortcut, [string]$ShortcutDirectory)
& {
$ErrorActionPreference = 'Stop'
$consensusRoot = if ($env:CONSENSUS_INSTALL_DIR) { [IO.Path]::GetFullPath($env:CONSENSUS_INSTALL_DIR) } else { Join-Path $env:USERPROFILE '.local\share\consensus-app' }
$consensusRelease = 'https://github.com/OSINT-Experts-Society/Consensus-OSINT/releases/latest/download'
$consensusSavedEnv = @{}
foreach ($name in @('UV_UNMANAGED_INSTALL', 'UV_PYTHON_INSTALL_DIR', 'UV_PYTHON_INSTALL_BIN', 'CONSENSUS_INSTALL_DIR')) {
    $consensusSavedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$consensusTemp = Join-Path ([IO.Path]::GetTempPath()) ('consensus-install-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $consensusRoot, $consensusTemp -Force | Out-Null
    $env:CONSENSUS_INSTALL_DIR = $consensusRoot
    $env:UV_UNMANAGED_INSTALL = Join-Path $consensusRoot 'uv'
    $env:UV_PYTHON_INSTALL_DIR = Join-Path $consensusRoot 'python'
    $env:UV_PYTHON_INSTALL_BIN = '0'
    $consensusManager = Join-Path $consensusTemp 'install-manager.py'
    if (-not $BundlePath -and $PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'release.json'))) {
        $BundlePath = $PSScriptRoot
    }
    try {
        if ($BundlePath) {
            $BundlePath = (Resolve-Path -LiteralPath $BundlePath).Path
            Copy-Item -LiteralPath (Join-Path $BundlePath 'install-manager.py') -Destination $consensusManager
        } else {
        Invoke-WebRequest "$consensusRelease/install-manager.py" -UseBasicParsing -OutFile $consensusManager
        }
    } catch {
        throw "Could not download the Consensus installer release. Check that a release is published at https://github.com/OSINT-Experts-Society/Consensus-OSINT/releases and that GitHub is reachable. No application update was installed."
    }
    $consensusUv = Join-Path $env:UV_UNMANAGED_INSTALL 'uv.exe'
    if (-not (Test-Path -LiteralPath $consensusUv)) {
        Write-Host 'Preparing the Consensus runtime...'
        Invoke-WebRequest 'https://astral.sh/uv/0.11.15/install.ps1' -UseBasicParsing -OutFile (Join-Path $consensusTemp 'uv-install.ps1')
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $consensusTemp 'uv-install.ps1')
        if ($LASTEXITCODE -ne 0) { throw 'Could not install the runtime helper.' }
    }
    $consensusArguments = @()
    if ($BundlePath) { $consensusArguments += @('--feed', $BundlePath) }
    if ($ConfigDirectory) { $consensusArguments += @('--config-dir', $ConfigDirectory) }
    if ($ReportsDirectory) { $consensusArguments += @('--reports-dir', $ReportsDirectory) }
    if ($env:CONSENSUS_INSTALL_EXTRAS) { $consensusArguments += @('--extras', $env:CONSENSUS_INSTALL_EXTRAS) }
    & $consensusUv run --no-config --no-project --managed-python --python 3.13 python -I $consensusManager @consensusArguments
    if ($LASTEXITCODE -ne 0) { throw 'Consensus installation failed. Any previous version remains selected.' }
    $consensusBin = Join-Path $consensusRoot 'bin'
    $consensusLauncher = Join-Path $consensusBin 'consensus.cmd'
    if (-not $NoShortcut -and $env:CONSENSUS_NO_SHORTCUT -ne '1') {
        try {
            $consensusShortcuts = if ($ShortcutDirectory) { [IO.Path]::GetFullPath($ShortcutDirectory) } else { [Environment]::GetFolderPath('Programs') }
            if (-not $consensusShortcuts) { throw 'Start menu folder is unavailable.' }
            New-Item -ItemType Directory -Path $consensusShortcuts -Force | Out-Null
            $consensusShell = New-Object -ComObject WScript.Shell
            $consensusShortcut = $consensusShell.CreateShortcut((Join-Path $consensusShortcuts 'Consensus.lnk'))
            $consensusShortcut.TargetPath = $consensusLauncher
            $consensusShortcut.WorkingDirectory = $env:USERPROFILE
            $consensusShortcut.Description = 'Consensus - OSINT Experts Society'
            $consensusShortcut.Save()
            Write-Host 'Start menu shortcut created. Search for Consensus to open it.'
        } catch {
            Write-Warning "Consensus is installed, but its Start menu shortcut could not be created: $($_.Exception.Message)"
        }
    }
    $consensusUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($env:CONSENSUS_NO_MODIFY_PATH -ne '1' -and $consensusBin -notin ($consensusUserPath -split ';')) {
        [Environment]::SetEnvironmentVariable('Path', ($consensusBin + ';' + $consensusUserPath), 'User')
    }
    if ($env:CONSENSUS_NO_MODIFY_PATH -ne '1' -and $consensusBin -notin ($env:Path -split ';')) {
        $env:Path = $consensusBin + ';' + $env:Path
    }
    if ($env:CONSENSUS_NO_MODIFY_PATH -eq '1') {
        Write-Host "Ready. Add $consensusBin to PATH or run its consensus.cmd launcher directly."
    } else {
        Write-Host 'Ready. Run consensus. To update later, run consensus update.'
    }
    if ($OfferLaunch -and (Read-Host 'Launch Consensus now? [Y/n]') -notmatch '^(n|no)$') {
        & $consensusLauncher
    }
} finally {
    foreach ($name in $consensusSavedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($name, $consensusSavedEnv[$name], 'Process')
    }
    # Delete only files we created in this unique temporary directory.
    foreach ($name in @('uv-install.ps1', 'install-manager.py')) {
        $consensusTempFile = Join-Path $consensusTemp $name
        if (Test-Path -LiteralPath $consensusTempFile) { Remove-Item -LiteralPath $consensusTempFile -Force }
    }
    if (Test-Path -LiteralPath $consensusTemp) { Remove-Item -LiteralPath $consensusTemp }
}
}
