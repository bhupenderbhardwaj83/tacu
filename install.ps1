# Guided TACU installer for Windows. It uses an isolated runtime, not system Python packages.
[CmdletBinding()]
param(
    [string]$Workspace,
    [switch]$UseCurrent,
    [switch]$SkipOllama,
    [switch]$SkipModels,
    [switch]$SkipDocker,
    [switch]$Force,
    [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$MinRamGB = 16
$MinDiskGB = 40
$SourceDir = $PSScriptRoot
$EnvFile = Join-Path $SourceDir ".env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*#' -or $_ -notmatch '=') { return }
        $pair = $_ -split '=', 2
        $name = $pair[0].Trim()
        $value = $pair[1].Trim().Trim('"').Trim("'")
        if ($name -and -not [Environment]::GetEnvironmentVariable($name)) {
            Set-Item -Path "Env:$name" -Value $value
        }
    }
}
$SearxngImage = "searxng/searxng:latest"
$SearxngContainer = "tacu-searxng"
$PrimaryModel = if ($env:TACU_MODEL) { $env:TACU_MODEL } else { "gemma4:12b" }
$BackupModel = if ($env:TACU_BACKUP_MODEL) { $env:TACU_BACKUP_MODEL } else { "qwen2.5-coder:7b" }
$InstallHome = if ($env:TACU_INSTALL_HOME) { $env:TACU_INSTALL_HOME } else { Join-Path $env:LOCALAPPDATA "TACU\runtime" }
$BinDir = if ($env:TACU_BIN_DIR) { $env:TACU_BIN_DIR } else { Join-Path $env:LOCALAPPDATA "TACU\bin" }
function Step($Number, $Message) { Write-Host "`n[$Number/7] $Message" -ForegroundColor Cyan }
function Ok($Message) { Write-Host "  [OK] $Message" -ForegroundColor Green }
function Info($Message) { Write-Host "  -> $Message" -ForegroundColor Gray }
function Wait-Until($Label, $Attempts, $DelaySeconds, [scriptblock]$Test) {
    Write-Host "  -> $Label" -NoNewline -ForegroundColor Gray
    for ($Attempt = 0; $Attempt -lt $Attempts; $Attempt++) {
        if (& $Test) { Write-Host "`r  [OK] $Label" -ForegroundColor Green; return $true }
        Write-Host "." -NoNewline -ForegroundColor Gray
        Start-Sleep -Seconds $DelaySeconds
    }
    Write-Host ""
    return $false
}
function Stop-Install($Message) { throw $Message }
$PythonBootstrap = if ($env:TACU_PYTHON_VERSION) { $env:TACU_PYTHON_VERSION } else { "3.14.7" }
function Get-PythonVersion([string]$Exe) {
    try {
        $text = & $Exe -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return "$text".Trim()
    } catch { return $null }
}
function Test-SupportedPython([string]$Exe) {
    if (-not $Exe) { return $false }
    if (-not (Test-Path $Exe)) {
        $found = Get-Command $Exe -ErrorAction SilentlyContinue
        if (-not $found) { return $false }
        $Exe = $found.Source
    }
    $ver = Get-PythonVersion $Exe
    if (-not $ver) { return $false }
    $parts = $ver.Split('.') | ForEach-Object { [int]$_ }
    if ($parts.Count -lt 2) { return $false }
    if ($parts[0] -ne 3 -or $parts[1] -lt 11) { return $false }
    & $Exe -c "import venv" 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}
function Find-SupportedPython {
    if ($env:TACU_PYTHON -and (Test-SupportedPython $env:TACU_PYTHON)) { return $env:TACU_PYTHON }
    foreach ($name in @("python3.14", "python3.13", "python3.12", "python3.11", "python", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and (Test-SupportedPython $cmd.Source)) { return $cmd.Source }
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        foreach ($tag in @("-3.14", "-3.13", "-3.12", "-3.11", "-3")) {
            try {
                $exe = & $py.Source $tag -c "import sys; print(sys.executable)" 2>$null
                if ($exe -and (Test-SupportedPython $exe.Trim())) { return $exe.Trim() }
            } catch { }
        }
    }
    foreach ($candidate in @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python314\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe")
    )) {
        if (Test-SupportedPython $candidate) { return $candidate }
    }
    return $null
}
function Install-PythonBootstrap {
    Info "Python 3.11+ was not found. Installing Python $PythonBootstrap from python.org..."
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    $file = if ($arch -eq "arm64") { "python-$PythonBootstrap-arm64.exe" } else { "python-$PythonBootstrap-amd64.exe" }
    $url = "https://www.python.org/ftp/python/$PythonBootstrap/$file"
    $installer = Join-Path $env:TEMP $file
    Info "Downloading $file..."
    Invoke-WebRequest $url -OutFile $installer
    Start-Process $installer -Wait -ArgumentList "/quiet","InstallAllUsers=0","PrependPath=1","Include_pip=1","Include_test=0","Include_launcher=1"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $env:Path = "$userPath;$machinePath;$env:Path"
}

function Show-Identity {
    # ASCII only: legacy consoles mangle box-drawing characters in a non-UTF-8 code page.
    Write-Host "`n+--------------+        <3" -ForegroundColor Cyan
    Write-Host "|  >_          |" -ForegroundColor Cyan
    Write-Host "|   ~     ~    |     t a c u" -ForegroundColor Cyan
    Write-Host "|      u       |     Terminal Ally & Companion Unit" -ForegroundColor Cyan
    Write-Host "+----------+   |" -ForegroundColor Cyan
    Write-Host "           +---+`n" -ForegroundColor Cyan
}

Show-Identity
Step 1 "Checking this computer"
$Computer = Get-CimInstance Win32_ComputerSystem
$RamGB = [math]::Floor($Computer.TotalPhysicalMemory / 1GB)
$DriveName = (Get-Item $env:USERPROFILE).PSDrive.Name
$DiskGB = [math]::Floor((Get-PSDrive $DriveName).Free / 1GB)
if ($RamGB -ge $MinRamGB) { Ok "Memory: $RamGB GB (16 GB minimum; 32 GB recommended)" } elseif (-not $Force) { Stop-Install "TACU needs at least 16 GB RAM. Use -Force only if you accept reduced reliability." }
if ($DiskGB -ge $MinDiskGB) { Ok "Free disk: $DiskGB GB (40 GB first install / 20 GB if stack present)" } elseif (-not $Force) { Stop-Install "TACU needs at least 40 GB free disk on first install (20 GB if Ollama+Docker+Gemma already present). Use -Force only with another model-storage plan." }
$Python = Find-SupportedPython
if ($Python) { Ok "Python $(Get-PythonVersion $Python) at $Python (3.11+ is supported)" }
elseif ($DryRun) { Info "Would install Python $PythonBootstrap from python.org"; $Python = "python" }
else {
    Install-PythonBootstrap
    $Python = Find-SupportedPython
    if (-not $Python) { Stop-Install "Python 3.11+ is required. Install Python $PythonBootstrap from https://www.python.org/downloads/ then rerun .\install.ps1" }
    Ok "Python $(Get-PythonVersion $Python) at $Python"
}
Ok "Prerequisites are ready"

Step 2 "Installing Terminal Ally & Companion Unit"
$VenvPython = Join-Path $InstallHome "venv\Scripts\python.exe"
$TacuExe = Join-Path $InstallHome "venv\Scripts\ticu.exe"
$TiLauncher = Join-Path $BinDir "ti.cmd"
$ExistingTi = Get-Command ti -ErrorAction SilentlyContinue
if ($DryRun) { Info "Would create an isolated TACU runtime and add $BinDir to your user PATH" }
else {
    New-Item -ItemType Directory -Force $InstallHome, $BinDir | Out-Null
    & $Python -m venv (Join-Path $InstallHome "venv")
    if ($LASTEXITCODE -ne 0) { Stop-Install "TACU could not create its private Python environment." }
    & $VenvPython -m pip install --quiet --no-cache-dir --disable-pip-version-check --no-deps --force-reinstall $SourceDir
    if ($LASTEXITCODE -ne 0) { Stop-Install "TACU could not install its application package." }
    Ok "Installed TACU in its own private application environment"
    "@echo off`r`n`"$TacuExe`" %*`r`n" | Set-Content -Encoding Ascii (Join-Path $BinDir "ticu.cmd")
    if (-not $ExistingTi -or $ExistingTi.Source -eq $TiLauncher) {
        Copy-Item (Join-Path $BinDir "ticu.cmd") $TiLauncher -Force
        Ok "Installed the conflict-checked short command: ti"
    } else { Info "Kept the existing ti command at $($ExistingTi.Source); use ticu on this computer" }
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $UserPath) { $UserPath = "" }
    if (($UserPath -split ';') -notcontains $BinDir) { [Environment]::SetEnvironmentVariable("Path", (($UserPath.TrimEnd(';') + ";" + $BinDir).Trim(';')), "User") }
    $env:Path = "$BinDir;$env:Path"
    Ok "The ticu command will work from every directory in new terminals"
    $ProfilePath = $PROFILE.CurrentUserAllHosts
    $ProfileDirectory = Split-Path -Parent $ProfilePath
    New-Item -ItemType Directory -Force -Path $ProfileDirectory | Out-Null
    if (-not (Test-Path $ProfilePath)) { New-Item -ItemType File -Force -Path $ProfilePath | Out-Null }
    if (-not (Select-String -Path $ProfilePath -SimpleMatch "# TACU completion and predictions" -Quiet)) {
        Add-Content -Path $ProfilePath -Value "`n# TACU completion and predictions`nInvoke-Expression (& ticu shell-init powershell | Out-String)"
    }
    Ok "Configured PowerShell completion and history predictions"
}

Step 3 "Setting up the AI foundation"
$OllamaCommand = Get-Command ollama -ErrorAction SilentlyContinue
if ($OllamaCommand) { Ok "Ollama is already installed: $(& $OllamaCommand.Source --version)" }
elseif ($SkipOllama) { Info "Skipped Ollama installation" }
elseif ($DryRun) { Info "Would install the latest official Ollama for Windows" }
else {
    $Installer = Join-Path $env:TEMP "OllamaSetup.exe"
    Invoke-WebRequest "https://ollama.com/download/OllamaSetup.exe" -OutFile $Installer
    Start-Process $Installer -Wait
    $OllamaPath = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
    if (-not (Test-Path $OllamaPath)) { Stop-Install "Ollama installation was not completed." }
    $env:Path = "$(Split-Path $OllamaPath);$env:Path"
    $OllamaCommand = [PSCustomObject]@{ Source = $OllamaPath }
    Ok "Ollama installed"
}

Step 4 "Setting up AI chat model"
if ($SkipModels) { Info "Skipped model downloads" }
elseif ($DryRun) { Info "Would use $PrimaryModel or $BackupModel if already installed; otherwise download $PrimaryModel only" }
elseif (-not $OllamaCommand) { Stop-Install "Ollama is unavailable. Finish installing it, then run: ticu setup" }
else {
    & $OllamaCommand.Source list 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Start-Process $OllamaCommand.Source -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
        if (-not (Wait-Until "Waiting for Ollama API" 30 1 { & $OllamaCommand.Source list 2>$null | Out-Null; $LASTEXITCODE -eq 0 })) {
            Stop-Install "Ollama did not start. Start Ollama, then run: ticu setup"
        }
    }
    $listed = & $OllamaCommand.Source list
    if ($listed | Select-String -SimpleMatch $PrimaryModel) { Ok "$PrimaryModel is already ready"; $script:ChatModel = $PrimaryModel }
    elseif ($listed | Select-String -SimpleMatch $BackupModel) { Ok "$BackupModel is already ready · using it as the chat model (not pulling $PrimaryModel)"; $script:ChatModel = $BackupModel }
    else {
        Info "Downloading $PrimaryModel (this can take several minutes)..."
        & $OllamaCommand.Source pull $PrimaryModel
        if ($LASTEXITCODE -ne 0) { Stop-Install "The AI model $PrimaryModel could not be installed." }
        Ok "$PrimaryModel is ready"
        $script:ChatModel = $PrimaryModel
    }
}

Step 5 "Setting up Docker Desktop + SearXNG"
if ($SkipDocker) { Info "Skipped Docker / SearXNG checks" }
elseif ($DryRun) {
    Info "Would verify Docker Desktop is running"
    Info "Would pull $SearxngImage and start $SearxngContainer on 127.0.0.1:8080 (or the next free port)"
}
elseif (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    if (-not $Force) { Stop-Install "Docker Desktop is required for ti web. Install it, then rerun .\install.ps1" }
    Info "Docker missing; continuing because -Force was set"
}
else {
    if (-not (Wait-Until "Waiting for Docker Desktop" 60 2 { docker info 2>$null | Out-Null; $LASTEXITCODE -eq 0 })) {
        if (-not $Force) { Stop-Install "Docker Desktop is installed but not running. Start it, then rerun .\install.ps1" }
        Info "Docker not ready; continuing because -Force was set"
    } else {
        docker image inspect $SearxngImage 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { Ok "$SearxngImage is already present" }
        else {
            Info "Pulling $SearxngImage (required for ti web)..."
            docker pull $SearxngImage
            if ($LASTEXITCODE -ne 0) { Stop-Install "Could not pull $SearxngImage" }
            Ok "$SearxngImage is ready"
        }
        Info "Starting $SearxngContainer (127.0.0.1:8080, or the next free port)..."
        if (Test-Path $VenvPython) {
            $msg = & $VenvPython -c "from tacu.configuration import ensure_searxng_container; ok, msg = ensure_searxng_container(); print(msg); raise SystemExit(0 if ok else 1)"
            if ($LASTEXITCODE -eq 0) { Ok "$msg" }
            elseif (-not $Force) { Stop-Install "Could not start $SearxngContainer. $msg" }
            else { Info "SearXNG not ready; continuing because -Force was set" }
        }
        elseif (-not $Force) { Stop-Install "TACU Python is missing; rerun .\install.ps1" }
    }
}

Step 6 "Preparing your project workspace"
if ($UseCurrent) { $Workspace = (Get-Location).Path }
if (-not $Workspace) {
    $DefaultWorkspace = Join-Path $HOME "TACU-Workspace"
    if ($DryRun) { $Workspace = $DefaultWorkspace }
    else { $Answer = Read-Host "Create the recommended workspace at $DefaultWorkspace? [Y/n]"; $Workspace = if ($Answer -match '^[Nn]') { (Get-Location).Path } else { $DefaultWorkspace } }
}
if ($DryRun) { Info "Would create/select workspace: $Workspace" }
else {
    New-Item -ItemType Directory -Force $Workspace | Out-Null
    & $TacuExe workspace create $Workspace --no-enter
    if ($LASTEXITCODE -ne 0) { Stop-Install "TACU could not prepare the requested project workspace." }
}

Step 7 "Verifying TACU"
if ($DryRun) { Info "Dry run complete; no files or settings were changed." }
else {
    & $TacuExe --version
    Info "Open a new terminal and run: ticu doctor"
    Info "Start anywhere with: ticu (or the short command: ti)"
    Info "Chat model: $(if ($script:ChatModel) { $script:ChatModel } else { $PrimaryModel }) · keep-alive 15m · timeout 15 min"
}
Write-Host "`nTACU installation complete." -ForegroundColor Green
