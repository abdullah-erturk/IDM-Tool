<# : hybrid batch + powershell script
@echo off
setlocal EnableDelayedExpansion

:: Admin privilege check and auto-elevation
net session >nul 2>&1
if errorlevel 1 (
	echo.
    echo	Administrator privileges required. Requesting elevation...
    if "%*"=="" (
        powershell -Command "Start-Process -FilePath '%~fs0' -Verb RunAs -WorkingDirectory '%~dp0'"
    ) else (
        powershell -Command "Start-Process -FilePath '%~fs0' -ArgumentList '%*' -Verb RunAs -WorkingDirectory '%~dp0'"
    )
    exit /b
)

:: If we reach here, we have admin privileges
echo.
echo	Administrator privileges required. Requesting elevation...
set		"PS_ARGS=%*"
powershell -noprofile -ExecutionPolicy Bypass -Command "& { $ScriptPath='%~f0'; iex((Get-Content('%~f0') -Raw)) }"
exit /b
#>

[CmdletBinding()]
param(
    [switch]$silent,
    [switch]$activate,
    [switch]$reset,
    [switch]$force,
    [switch]$help,
    [switch]$version,
    [switch]$DebugMode
)

# Manual parameter parsing for hybrid script compatibility
# Get parameters from environment variable (set by batch script)
if ($env:PS_ARGS) {
    $args = $env:PS_ARGS.Split(' ') | Where-Object { $_.Trim() -ne '' }
} else {
    $args = @()
}
if ($args) {
    Write-Host "DEBUG: Processing $($args.Count) arguments..." -ForegroundColor Yellow
    foreach ($arg in $args) {
        Write-Host "DEBUG: Processing arg: '$arg'" -ForegroundColor Cyan
        switch -Regex ($arg) {
            '^-?silent$'     { $silent = $true; Write-Host "DEBUG: Set silent = true" -ForegroundColor Green }
            '^-?activate$'   { $activate = $true; Write-Host "DEBUG: Set activate = true" -ForegroundColor Green }
            '^-?reset$'      { $reset = $true; Write-Host "DEBUG: Set reset = true" -ForegroundColor Green }
            '^-?force$'      { $force = $true; Write-Host "DEBUG: Set force = true" -ForegroundColor Green }
            '^-?help$'       { $help = $true; Write-Host "DEBUG: Set help = true" -ForegroundColor Green }
            '^-?version$'    { $version = $true; Write-Host "DEBUG: Set version = true" -ForegroundColor Green }
            '^-?debug$'      { $DebugMode = $true; Write-Host "DEBUG: Set DebugMode = true" -ForegroundColor Green }
            '^-?DebugMode$'  { $DebugMode = $true; Write-Host "DEBUG: Set DebugMode = true" -ForegroundColor Green }
        }
    }
} 

$Title = "IDM Tool | made by Abdullah ERTÜRK"
Clear-Host

$host.ui.rawui.windowtitle = $title

# UI debug logger (moved to top for early access)
$script:EnableUiDebug = $false
function Log-UI {
    param([string]$Message)
    try {
        $ts = Get-Date -Format 'HH:mm:ss'
        $line = "[$ts] $Message"
        
        # Command Preview - always show all messages
        if ($script:EnableUiDebug -and $tbPreview -and -not $tbPreview.IsDisposed) {
            $tbPreview.AppendText($line + "`r`n")
            $tbPreview.SelectionStart = $tbPreview.TextLength
            $tbPreview.ScrollToCaret()
        }
        
        # Debug Output - filter messages for simplicity
        if ($chkDebug -and $chkDebug.Checked -and $tbDebugOutput -and -not $tbDebugOutput.IsDisposed) {
            # Only show important messages, filter out detailed DEBUG messages
            if ($Message -match "^DEBUG:" -and 
                -not ($Message -match "(Starting|completed|SUCCESS|FAILED|ERROR|Exception)" -or
                      $Message -match "(operation|activate|reset|download test)")) {
                # Skip detailed debug messages
                return
            }
            
            # Simplify remaining messages
            $simplifiedMessage = $Message
            if ($Message -match "^DEBUG: Starting (.+) \(.*\)") {
                $simplifiedMessage = "Starting: " + $matches[1]
            }
            elseif ($Message -match "^DEBUG: (.+) completed successfully") {
                $simplifiedMessage = "SUCCESS: " + $matches[1]
            }
            elseif ($Message -match "^DEBUG: (.+) failed") {
                $simplifiedMessage = "ERROR: " + $matches[1]
            }
            elseif ($Message -match "Started operation: (\w+) \(.*\)") {
                $simplifiedMessage = "Operation: " + $matches[1].ToUpper()
            }
            elseif ($Message -match "Completed successfully") {
                $simplifiedMessage = "SUCCESS: Operation completed"
            }
            
            $simplifiedLine = "[$ts] $simplifiedMessage"
            $tbDebugOutput.AppendText($simplifiedLine + "`r`n")
            $tbDebugOutput.SelectionStart = $tbDebugOutput.TextLength
            $tbDebugOutput.ScrollToCaret()
        }
        
        Write-Host $line
    } catch {
        # Fallback to Write-Host if UI components not available
        Write-Host "[$ts] $Message"
    }
}

# Request-AdminPrivileges function definition (moved to top for early access)
function Request-AdminPrivileges {
    param([string]$ScriptPath = $PSCommandPath, [array]$Arguments = @())
    
    if (-not (Test-IsAdministrator)) {
        Write-Host "Administrator privileges required. Requesting elevation..." -ForegroundColor Yellow
        
        try {
            $argString = ""
            if ($Arguments.Count -gt 0) {
                $argString = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
            }
            
            $startParams = @{
                FilePath = 'powershell.exe'
                ArgumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"") + $Arguments
                Verb = 'RunAs'
                WindowStyle = 'Normal'
            }
            
            Start-Process @startParams
            Write-Host "Script restarted with administrator privileges." -ForegroundColor Green
            exit 0
        } catch {
            Write-Host "Failed to request administrator privileges: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Please run the script as Administrator manually." -ForegroundColor Yellow
            return $false
        }
    }
    return $true
}

function Test-IsAdministrator { 
    $id=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) 
}

# Automatic administrator privilege check and elevation
if (-not (Request-AdminPrivileges -ScriptPath $PSCommandPath -Arguments $args)) {
    exit 1
}

# Signature Verification (disabled by default for cross-platform compatibility)
function Verify-ScriptIntegrity {
    param([switch]$EnableCheck)
    
    if (-not $EnableCheck) {
        Write-Host "Script integrity check disabled (cross-platform mode)" -ForegroundColor Gray
        return
    }
    
    $enc_cert='LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURuekNDQW9lZ0F3SUJBZ0lVV3hmcmJRNDROcjNaYTF3QXE2dWJnVWoxWjdNd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1h6RUxNQWtHQTFVRUJoTUNWVk14Q3pBSkJnTlZCQWdNQWtOQk1SVXdFd1lEVlFRSERBeFRZVzVHY21GdQpZMmx6WTI4eEREQUtCZ05WQkFvTUEwbEJVekVlTUJ3R0ExVUVBd3dWU1VSdExVRmpkR2wyWVhScGIyNHRVMk55CmFYQjBNQjRYRFRJMU1EZ3lNREl5TWpjek1Gb1hEVEkyTURneU1ESXlNamN6TUZvd1h6RUxNQWtHQTFVRUJoTUMKVlZNeEN6QUpCZ05WQkFnTUFrTkJNUlV3RXdZRFZRUUhEQXhUWVc1R2NtRnVZMmx6WTI4eEREQUtCZ05WQkFvTQpBMGxCVXpFZU1Cd0dBMVVFQXd3VlNVUk5MVUZqZEdsMllYUnBiMjR0VTJOeWFYQjBNSUlCSWpBTkJna3Foa2lHCjl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF1R3pMZVgzLzNwMEZEOC9rRjZBRllPWDJDUXpEV0puRDZsQSsKWHhMcS8rbTQ5dHd3eWYwK2NkVW9Fd2V4VFY5NEZteUQzek1iMnQ3aGZHVVovNjBjZ1NVRm1OWk1TakQ5YkM2NwpYRXhCQ0FhaFAwaEZDUXRhTmJ3Zm44eWphS0JUQkdRUXAvVGx2WkdIZWx2azVvRFJlZnFFRE5GK2E3T2hWRVF0ClAyUjk2dVJrMEwxeUd4LzlSY3ZIbVpuWHJ0UUd4Ry9pc01HbE4xalZzOVFXOVRWVkwydVIyVGdBeUNHS3E5dmEKSGE5dGFXWTlWK0tiT25IWWt2dHF3cEFkK0o0WVZBV2xVQmluWGlTbEx3OFJEQ2ZSUDBGSUFKOEQ='
    $enc_hash='ZDczMDYwODE1ZmZhZjJkYjlmYWVmNTQwNTEyNmMzOTZmNjIzMjgzOWMwNWMzNWMwODMyYzRmNDAxMWRkN2FjOA=='
    try {
        $scriptContent = Get-Content $PSCommandPath -Raw -ErrorAction SilentlyContinue
        $currentHash = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash.ToLower()
        $expectedHash = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_hash))
        if ($currentHash -ne $expectedHash -and !$script:SkipIntegrityCheck) {
            Write-Warning "Script integrity verification failed. File may have been modified."
            Write-Host "Expected: $expectedHash" -ForegroundColor Yellow
            Write-Host "Current:  $currentHash" -ForegroundColor Red
            if (-not $Force) {
                throw "Integrity check failed. Use -Force to bypass (not recommended)."
            }
        } else {
            Write-Host "Script integrity verified successfully." -ForegroundColor Green
        }
    } catch {
        if (-not $Force) {
            Write-Error "Signature verification failed: $($_.Exception.Message)"
            exit 1
        } else {
            Write-Warning "Signature verification bypassed with -Force flag."
        }
    }
}


# Command line execution logic will be moved after function definitions

# If no command line args, continue to GUI
Write-Host ""
Write-Host "	GUI mode..." -ForegroundColor Yellow
Add-Type -AssemblyName System.Windows.Forms
# --- Varsayýlan lisans sahibi adýný belirleyen yardýmcý ---
function Get-DefaultLicenseOwner {
    param([string]$Fallback = 'Kullanici')
    try {
        # 1) Etkileþimli kullanýcý (SYSTEM ile çalýþýrken iþ görür)
        $csUser = $null
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs -and $cs.UserName) { $csUser = $cs.UserName }
        } catch {
            try {
                $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
                if ($cs -and $cs.UserName) { $csUser = $cs.UserName }
            } catch {}
        }

        # 2) Adayý belirle
        $candidate = if ($csUser) { $csUser }
                     elseif ($env:USERNAME) { $env:USERNAME }
                     else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }

        # 3) DOMAIN\kadi formatýný sadeleþtir
        if ($candidate -like '*\*') { $candidate = $candidate.Split('\')[-1] }

        # 4) Boþsa yedek
        if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = $Fallback }

        return $candidate
    } catch {
        return $Fallback
    }
}

# --- InputBox Yardýmcý Fonksiyonu ---
function Show-InputBox {
    param(
        [string]$Title  = 'License owner',
        [string]$Prompt = 'Enter the license owner name:',
        [string]$Default = $null,
        [switch]$TopMost
    )

    # 1) Microsoft.VisualBasic.InputBox denenir (kolay yol)
    try {
        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        $value = [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, $Title, $Default)
        if ($null -ne $value -and $value.Trim().Length -gt 0) { return $value.Trim() }
        return $null
    } catch {
        # 2) Fallback: WinForms ile basit bir girdi penceresi
        try {
            $inputForm = New-Object System.Windows.Forms.Form
            $inputForm.Text = $Title
            $inputForm.FormBorderStyle = 'FixedDialog'
            $inputForm.MaximizeBox = $false
            $inputForm.MinimizeBox = $false
            $inputForm.StartPosition = 'CenterScreen'
            $inputForm.ClientSize = New-Object System.Drawing.Size(380, 140)
            $inputForm.TopMost = [bool]$TopMost

            # Mevcut ana form varsa ebeveyn olarak ayarla (merkezlenmesi için)
            try { if ($form -and -not $form.IsDisposed) { $null = $inputForm.ShowInTaskbar = $false } } catch {}

            $lbl = New-Object System.Windows.Forms.Label
            $lbl.AutoSize = $true
            $lbl.Text = $Prompt
            $lbl.Location = New-Object System.Drawing.Point(12, 12)

            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Size = New-Object System.Drawing.Size(350, 22)
            $tb.Location = New-Object System.Drawing.Point(15, 40)
            if ($Default) { $tb.Text = $Default }

            $btnOK = New-Object System.Windows.Forms.Button
            $btnOK.Text = 'Tamam'
            $btnOK.Location = New-Object System.Drawing.Point(190, 80)
            $btnOK.Size = New-Object System.Drawing.Size(80, 28)
            $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK

            $btnCancel = New-Object System.Windows.Forms.Button
            $btnCancel.Text = 'Ýptal'
            $btnCancel.Location = New-Object System.Drawing.Point(285, 80)
            $btnCancel.Size = New-Object System.Drawing.Size(80, 28)
            $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

            $inputForm.AcceptButton = $btnOK
            $inputForm.CancelButton = $btnCancel

            $inputForm.Controls.AddRange(@($lbl, $tb, $btnOK, $btnCancel))

            # Ana form varsa ona göre modal göster
            $result = try {
                if ($form -and -not $form.IsDisposed) {
                    $inputForm.StartPosition = 'CenterParent'
                    $inputForm.ShowDialog($form)
                } else {
                    $inputForm.ShowDialog()
                }
            } catch {
                $inputForm.ShowDialog()
            }

            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $text = ($tb.Text).Trim()
                if ($text.Length -gt 0) { return $text }
            }
            return $null
        } catch {
            return $null
        }
    }
}

Add-Type -AssemblyName System.Drawing

try {
    Add-Type -ReferencedAssemblies @("System.Windows.Forms", "System.Drawing") -TypeDefinition @"
using System;
using System.Drawing;
using System.Windows.Forms;

namespace CustomControls.V2
{
    public class SegmentedProgressBarV2 : ProgressBar
    {
        public int SegmentCount { get; set; }
        public int SegmentSpacing { get; set; }
        public bool ShowPercentageText { get; set; }

        public SegmentedProgressBarV2()
        {
            this.SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            this.DoubleBuffered = true;
            this.SegmentCount = 40;
            this.SegmentSpacing = 3;
            this.ShowPercentageText = false;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Rectangle rect = this.ClientRectangle;
            e.Graphics.Clear(this.BackColor);

            int segmentHeight = rect.Height - 6;
            int segmentWidth = segmentHeight;
            int spacing = Math.Max(0, this.SegmentSpacing);
            int availableWidth = rect.Width - 6;
            int maxByWidth = (availableWidth + spacing) / (segmentWidth + spacing);
            int segments = Math.Max(1, Math.Min(this.SegmentCount, maxByWidth));

            double ratio = 0.0;
            if (this.Maximum > this.Minimum)
            {
                ratio = (double)(this.Value - this.Minimum) / (double)(this.Maximum - this.Minimum);
            }
            int filledSegments = (int)Math.Round(segments * ratio);

            int gaps = segments - 1;
            int desiredSpacing = spacing;
            if (gaps > 0)
            {
                int maxSpacing = (availableWidth - (segments * segmentWidth)) / gaps;
                if (maxSpacing < 0) maxSpacing = 0;
                spacing = Math.Max(0, Math.Min(desiredSpacing, maxSpacing));
            }
            else { spacing = 0; }
            int totalSegmentsWidth = (segments * segmentWidth) + (gaps * spacing);
            int startX = 3 + ((availableWidth - totalSegmentsWidth) / 2);
            int x = startX;
            using (Brush fill = new SolidBrush(this.ForeColor))
            using (Pen border = new Pen(Color.FromArgb(120, 120, 120)))
            {
                for (int i = 0; i < segments; i++)
                {
                    Rectangle segRect = new Rectangle(x, 3, segmentWidth, segmentHeight);
                    if (i < filledSegments)
                    {
                        e.Graphics.FillRectangle(fill, segRect);
                    }
                    e.Graphics.DrawRectangle(border, segRect);
                    x += segmentWidth + spacing;
                }
            }

            if (this.ShowPercentageText)
            {
                string text = ((int)(ratio * 100)).ToString() + "%";
                using (Brush tb = new SolidBrush(this.ForeColor))
                {
                    StringFormat sf = new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                    e.Graphics.DrawString(text, this.Font, tb, rect, sf);
                }
            }
        }
    }
}
"@
} catch {}

[System.Windows.Forms.Application]::EnableVisualStyles()

# Functions moved to the top of the file to avoid "not recognized" errors
function Test-HKCUSync { 
    try { 
        $testKey = "IAS_SYNC_TEST"; 
        Remove-Item -Path "HKCU:Software\$testKey" -Force -ErrorAction SilentlyContinue; 
        $null = New-Item -Path "HKCU:Software\$testKey" -Force; 
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; 
        $hkuPath = "Registry::HKEY_USERS\$sid\Software\$testKey"; 
        $syncWorks = Test-Path $hkuPath; 
        Remove-Item -Path "HKCU:Software\$testKey" -Force -ErrorAction SilentlyContinue; 
        return $syncWorks 
    } catch { 
        return $false 
    } 
}
function Get-IDMPath {
    try {
        $k1=Get-ItemProperty -Path 'HKCU:Software\DownloadManager' -ErrorAction SilentlyContinue; if ($k1 -and $k1.ExePath -and (Test-Path $k1.ExePath)) { return $k1.ExePath }
        $k2=Get-ItemProperty -Path 'HKCU:Software\Wow6432Node\DownloadManager' -ErrorAction SilentlyContinue; if ($k2 -and $k2.ExePath -and (Test-Path $k2.ExePath)) { return $k2.ExePath }
        $pf=[Environment]::GetFolderPath('ProgramFilesX86'); if ([string]::IsNullOrEmpty($pf)) { $pf=[Environment]::GetFolderPath('ProgramFiles') }
        $p=Join-Path $pf 'Internet Download Manager/IDMan.exe'; if (Test-Path $p) { return $p } ; return ''
    } catch { return '' }
}

function Test-InternetConnectivity { try { $p=new-object System.Net.NetworkInformation.Ping; ($p.Send('internetdownloadmanager.com',5000)).Status -eq 'Success' } catch { $false } }
function Stop-IDMProcess { 
    try { 
        $processes = Get-Process -Name 'idman' -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            try {
                $process.Kill()
                $process.WaitForExit()
            } catch {}
        }
        # Alternative method using taskkill
        & taskkill.exe /f /im idman.exe 2>$null | Out-Null
    } catch {} 
}

function Stop-AllIDMProcesses {
    $processes = @(
        "IDMan.exe",
        "IEMonitor.exe",
        "IDMGrHlp.exe",
        "idmBroker.exe",
        "IDMMsgHost.exe",
        "MediumILStart.exe",
        "IDMIntegrator64.exe"
    )

# Always-unattended IDM installer
function Install-IDMUnattended {
    param([string]$InstallerPath, [switch]$DebugMode)
    $argSets = @(
        '/skipdlgs /silent',
        '/silent',
        '/S',
        '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
    )
    foreach($arg in $argSets){
        try {
            if ($DebugMode) { Log-UI "DEBUG: Trying IDM installer with args: $arg" }
            $proc = Start-Process -FilePath $InstallerPath -ArgumentList $arg -PassThru -Wait -WindowStyle Hidden
            $exit = $proc.ExitCode
            if ($DebugMode) { Log-UI "DEBUG: Installer exited with code $exit" }
            # Validate installation by locating IDMan.exe
            $idmPath = Get-IDMPath
            if ($idmPath -and (Test-Path $idmPath)){
                if ($DebugMode) { Log-UI "DEBUG: IDM detected at: $idmPath (args used: $arg)" }
                return @{ Success=$true; Args=$arg; ExitCode=$exit; Path=$idmPath }
            }
        } catch {
            if ($DebugMode) { Log-UI "DEBUG: Install attempt failed for args [$arg] - $($_.Exception.Message)" }
        }
    }
    return @{ Success=$false }
}
    foreach ($proc in $processes) {
        try {
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        } catch {}
        try {
            & taskkill.exe /f /im $proc 2>$null | Out-Null
        } catch {}
    }
}

function Get-Arch { try { (Get-ItemProperty 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE } catch { 'x64' } }
function Export-RegistryBackup { try { $ts=(Get-Date).ToString('yyyyMMdd-HHmmssfff'); $tmp=[IO.Path]::GetTempPath(); $arch=Get-Arch; if ($arch -eq 'x86') { $clsid='HKCU\Software\Classes\CLSID' } else { $clsid='HKCU\Software\Classes\WOW6432Node\CLSID' }; & reg.exe export $clsid "$tmp`_Backup_CLSID_$ts.reg" /y | Out-Null } catch {} }

# Always-unattended IDM installer (global scope)
function Install-IDMUnattended {
    param([string]$InstallerPath, [switch]$DebugMode)
    $argSets = @(
        '/skipdlgs /silent',
        '/silent',
        '/S',
        '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
    )
    foreach($arg in $argSets){
        try {
            if ($DebugMode) { Log-UI "DEBUG: Trying IDM installer with args: $arg" }
            $proc = Start-Process -FilePath $InstallerPath -ArgumentList $arg -PassThru -Wait -WindowStyle Hidden
            $exit = $proc.ExitCode
            if ($DebugMode) { Log-UI "DEBUG: Installer exited with code $exit" }
            $idmPath = Get-IDMPath
            if ($idmPath -and (Test-Path $idmPath)){
                if ($DebugMode) { Log-UI "DEBUG: IDM detected at: $idmPath (args used: $arg)" }
                return @{ Success=$true; Args=$arg; ExitCode=$exit; Path=$idmPath }
            }
        } catch {
            if ($DebugMode) { Log-UI "DEBUG: Install attempt failed for args [$arg] - $($_.Exception.Message)" }
        }
    }
    return @{ Success=$false }
}

# function Add-RequiredRegistryKeys
function Add-RequiredRegistryKeys { 
    param([switch]$Silent,[switch]$Force,[switch]$DebugMode)
    $enc_data='QWRkLVJlcXVpcmVkUmVnaXN0cnlLZXlz'
    $x1=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('dHJ5IHsgJGFyY2g9R2V0LUFyY2g='))
    $x2=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aWYgKCRhcmNoIC1lcSAneDg2Jykge2w='))
    $x3=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('JGhrbG09J0hLTE06U09GVFdBUkUvSW50ZXJuZXQgRG93bmxvYWQgTWFuYWdlcic='))
    $x4=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('fSBlbHNlIHsgJGhrbG09J0hLTE06U09GVFdBUkUvV293NjQzMk5vZGUvSW50ZXJuZXQgRG93bmxvYWQgTWFuYWdlcicgfQ=='))
    
    if ($DebugMode) { Log-UI ('DEBUG: Starting ' + [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_data)) + " (Silent=$Silent, Force=$Force)") }
    try { 
        $arch=Get-Arch; if ($DebugMode) { Log-UI "DEBUG: System architecture: $arch" }
        if ($arch -eq 'x86') { $hklm='HKLM:SOFTWARE/Internet Download Manager' } else { $hklm='HKLM:SOFTWARE/Wow6432Node/Internet Download Manager' }
        if ($DebugMode) { Log-UI "DEBUG: Target registry path: $hklm" }
        $keyCreated = New-Item -Path $hklm -Force -ErrorAction SilentlyContinue
        if ($keyCreated) { if ($DebugMode) { Log-UI "DEBUG: Successfully created registry key: $hklm" } elseif (-not $Silent) { Log-UI "Created IDM registry key" } } else { if ($DebugMode) { Log-UI "DEBUG: Failed to create registry key: $hklm" } elseif (-not $Silent -and -not $Force) { Log-UI "Warning: Could not create IDM registry key" } }
        $propertyCreated = New-ItemProperty -Path $hklm -Name 'AdvIntDriverEnabled2' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
        if ($propertyCreated) { if ($DebugMode) { Log-UI "DEBUG: Successfully created registry property: AdvIntDriverEnabled2 = 1" } elseif (-not $Silent) { Log-UI "Set AdvIntDriverEnabled2 = 1" } } else { if ($DebugMode) { Log-UI "DEBUG: Failed to create registry property: AdvIntDriverEnabled2" } elseif (-not $Silent -and -not $Force) { Log-UI "Warning: Could not set AdvIntDriverEnabled2 property" } }
        if ($Force) { if ($DebugMode) { Log-UI "DEBUG: Force mode - applying additional registry settings" }; try { New-ItemProperty -Path $hklm -Name 'IEMonitoringEnabled' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null; New-ItemProperty -Path $hklm -Name 'FireFoxMonitoringEnabled' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null; New-ItemProperty -Path $hklm -Name 'ChromeMonitoringEnabled' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null; if ($DebugMode) { Log-UI "DEBUG: Force mode - additional browser monitoring settings applied" } elseif (-not $Silent) { Log-UI "Applied enhanced browser integration settings" } } catch { if ($DebugMode) { Log-UI "DEBUG: Force mode - failed to apply additional settings: $($_.Exception.Message)" } } }
        if ($DebugMode) { Log-UI "DEBUG: Add-RequiredRegistryKeys completed successfully" }
    } catch { if ($DebugMode) { Log-UI "DEBUG: Exception in Add-RequiredRegistryKeys: $($_.Exception.Message)"; Log-UI "DEBUG: Stack trace: $($_.ScriptStackTrace)" } elseif (-not $Silent) { Log-UI "Error adding required registry keys: $($_.Exception.Message)" } } 
}
# function Remove-IDMRegistryKeys
function Remove-IDMRegistryKeys {
    param([switch]$Silent,[switch]$Force,[switch]$DebugMode)
    $enc_func='UmVtb3ZlLUlETVJlZ2lzdHJ5S2V5cw=='
    $enc_hkcu='SEtDVTpTb2Z0d2FyZVxEb3dubG9hZE1hbmFnZXI='
    if ($DebugMode) { Log-UI ('DEBUG: Starting ' + [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_func)) + " (Silent=$Silent, Force=$Force)") }
    $HKCUsync = Test-HKCUSync; $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $arch = Get-Arch
    if ($DebugMode) { Log-UI "DEBUG: HKCUsync=$HKCUsync, SID=$sid, Architecture=$arch" }
    $keysToDelete = @('HKCU:Software\DownloadManager:FName','HKCU:Software\DownloadManager:LName','HKCU:Software\DownloadManager:Email','HKCU:Software\DownloadManager:Serial','HKCU:Software\DownloadManager:scansk','HKCU:Software\DownloadManager:tvfrdt','HKCU:Software\DownloadManager:radxcnt','HKCU:Software\DownloadManager:LstCheck','HKCU:Software\DownloadManager:ptrk_scdt','HKCU:Software\DownloadManager:LastCheckQU')
    if ($arch -eq 'x86') { $keysToDelete += 'HKLM:SOFTWARE\Internet Download Manager' } else { $keysToDelete += 'HKLM:SOFTWARE\Wow6432Node\Internet Download Manager' }
    if ($DebugMode) { Log-UI "DEBUG: Processing $($keysToDelete.Count) registry keys" }
    $removedCount = 0
    foreach ($keyPath in $keysToDelete) { try { if ($keyPath.Contains(':') -and !$keyPath.EndsWith(':')) { $parts = $keyPath.Split(':'); if ($parts.Count -eq 3) { $regPath = $parts[0] + ':' + $parts[1]; $valueName = $parts[2]; $exists = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue; if ($exists) { Remove-ItemProperty -Path $regPath -Name $valueName -Force:$Force -ErrorAction SilentlyContinue; $removedCount++; if ($DebugMode) { Log-UI "DEBUG: Removed registry value: $keyPath" } elseif (-not $Silent) { Log-UI "Removed registry value: $valueName" } } } else { if (Test-Path $keyPath) { Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue; $removedCount++; if ($DebugMode) { Log-UI "DEBUG: Removed registry key: $keyPath" } elseif (-not $Silent) { Log-UI "Removed registry key: $keyPath" } } } } } catch { if ($DebugMode) { Log-UI "DEBUG: Error removing $keyPath - $($_.Exception.Message)" } elseif (-not $Silent) { Log-UI "Warning: Could not remove $keyPath" } } }
    if (-not $HKCUsync) { if ($DebugMode) { Log-UI "DEBUG: HKCU/HKU not synced, using reg.exe for HKU cleanup" }; $hkuValues = @('FName','LName','Email','Serial','scansk','tvfrdt','radxcnt','LstCheck','ptrk_scdt','LastCheckQU'); foreach ($valueName in $hkuValues) { try { $regArgs = @("delete", "HKU\$sid\SOFTWARE\DownloadManager", "/v", $valueName, "/f"); if ($Force) { $regArgs += "/reg:64" }; $result = & reg.exe $regArgs 2>$null; if ($LASTEXITCODE -eq 0) { $removedCount++; if ($DebugMode) { Log-UI "DEBUG: Removed HKU value: $valueName" } elseif (-not $Silent) { Log-UI "Removed HKU value: $valueName" } } } catch { if ($DebugMode) { Log-UI "DEBUG: Error removing HKU value $valueName - $($_.Exception.Message)" } } } }
    if ($DebugMode) { Log-UI "DEBUG: Remove-IDMRegistryKeys completed. Removed $removedCount items" } elseif (-not $Silent) { Log-UI "Registry cleanup completed ($removedCount items removed)" }
}
function Set-RegistryValueSimple($subKey,$name,$value,$rootHive="HKCU"){ 
    try { 
        if ($rootHive.StartsWith("HKU:")) {
            # Use reg.exe for HKU paths
            $regPath = $rootHive.Replace("HKU:", "HKU\") + "\" + $subKey.Replace("/", "\")
            & reg.exe add $regPath /v $name /t REG_SZ /d $value /f 2>$null | Out-Null
        } else {
            # Use reg.exe for all paths to avoid PowerShell provider issues
            $regPath = $rootHive.Replace(":", "") + "\" + $subKey.Replace("/", "\")
            & reg.exe add $regPath /v $name /t REG_SZ /d $value /f 2>$null | Out-Null
        }
    } catch {} 
}

# function Register-IDM
function Register-IDM {
    param([string]$LicenseName)

    try {
                if (-not $LicenseName -or [string]::IsNullOrWhiteSpace($LicenseName)) {
                        if (Get-Command Get-DefaultLicenseOwner -ErrorAction SilentlyContinue) {
                                $LicenseName = Get-DefaultLicenseOwner
                        } else {
                                $LicenseName = if ($env:USERNAME) { $env:USERNAME } else { 'Kullanici' }
                        }
                }


        # (Ýsteðe baðlý) e-posta üretimi
        $email = "$LicenseName@ornek.com"

        # --- Orijinal serial üretim mantýðý korunuyor ---
        $r = New-Object Random
        $enc_chars = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5'
        $chars = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_chars))).ToCharArray()
        $sb = New-Object System.Text.StringBuilder
        1..20 | ForEach-Object { [void]$sb.Append($chars[$r.Next($chars.Length)]) }
        $k = $sb.ToString()
        $serial = "{0}-{1}-{2}-{3}" -f $k.Substring(0,5),$k.Substring(5,5),$k.Substring(10,5),$k.Substring(15,5)
        # -------------------------------------------------

        $HKCUsync = Test-HKCUSync
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

        # SADECE FName + Email + Serial yaz (LName yazma!)
        Set-RegistryValueSimple 'Software/DownloadManager' 'FName'  $LicenseName
        Set-RegistryValueSimple 'Software/DownloadManager' 'Email'  $email
        Set-RegistryValueSimple 'Software/DownloadManager' 'Serial' $serial

        # HKU senk yoksa HKU'ya da yaz
        if (-not $HKCUsync) {
            Set-RegistryValueSimple "SOFTWARE\DownloadManager" 'FName'  $LicenseName "HKU:\$sid"
            Set-RegistryValueSimple "SOFTWARE\DownloadManager" 'Email'  $email      "HKU:\$sid"
            Set-RegistryValueSimple "SOFTWARE\DownloadManager" 'Serial' $serial     "HKU:\$sid"
        }

        # Eski/yanlýþ yazýlmýþ LName varsa temizle ki " /f" v.s. görünmesin
        try {
            Remove-ItemProperty -Path 'HKCU:\Software\DownloadManager' -Name 'LName' -ErrorAction SilentlyContinue
            if (-not $HKCUsync) {
                & reg.exe delete "HKU\$sid\SOFTWARE\DownloadManager" /v LName /f 2>$null | Out-Null
            }
        } catch {}

        Write-Host "Licensing completed!" -ForegroundColor Green
        Write-Host "License Owner: $LicenseName"
        Write-Host "Serial: $serial"
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Tek seferlik cache'li lisans sahibi alma ---
$script:LicenseOwner = $null
function Get-LicenseOwnerName {
    param([switch]$Silent)

    # Cache varsa direkt dön
    if ($script:LicenseOwner -and -not [string]::IsNullOrWhiteSpace($script:LicenseOwner)) {
        return $script:LicenseOwner
    }

    # Sessiz mod: soru sormadan Windows kullanýcý adýný kullan ve cache'le
    if ($Silent) {
        $script:LicenseOwner = Get-DefaultLicenseOwner
        return $script:LicenseOwner
    }

    # Varsayýlan öneri olarak Windows kullanýcý adýný kullan
    $defaultName = Get-DefaultLicenseOwner

    # InputBox ile ismi al (daha önce verdiðim Show-InputBox fonksiyonunu kullanýr)
    $owner = Show-InputBox -Title 'License owner' -Prompt 'Enter the license owner name:' -Default $defaultName -TopMost

    # Ýptal/boþ ise default olarak Windows kullanýcýsýný kullan ve cache'le
    if ([string]::IsNullOrWhiteSpace($owner)) {
        $script:LicenseOwner = $defaultName
        return $script:LicenseOwner
    }

    # Tek seferlik cache
    $script:LicenseOwner = $owner.Trim()
    return $script:LicenseOwner
}

# function Invoke-CLSIDProcessing
function Invoke-CLSIDProcessing {
    param([bool]$Delete,[bool]$ForceDelete=$false,[switch]$Silent,[switch]$Force,[switch]$DebugMode)
    $enc_func='SW52b2tlLUNMU0lEUHJvY2Vzc2luZw=='
    $enc_msg1='RGVsZXRpbmcgSURNIENMU0lEIFJlZ2lzdHJ5IEtleXMu'
    $enc_msg2='TG9ja2luZyBJRE0gQ0xTSUQgUmVnaXN0cnkgS2V5cy4u'
    $enc_msg3='SURNIENMU0lEIFJlZ2lzdHJ5IEtleXMgYXJlIG5vdCBmb3VuZC4='
    if ($DebugMode) { Log-UI ("DEBUG: Starting " + [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_func)) + " (Delete=$Delete, ForceDelete=$ForceDelete, Silent=$Silent, Force=$Force)") }
    try { $sid=(New-Object System.Security.Principal.WindowsIdentity $env:UserName).User.Value } catch { try { $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { $sid=$null } }
    $HKCUsync = Test-HKCUSync; $arch=Get-Arch
    if ($DebugMode) { Log-UI "DEBUG: System Architecture: $arch" }
    if ($arch -eq 'x86') { $regPaths=@('HKCU:Software/Classes/CLSID',"Registry::HKEY_USERS/$sid/Software/Classes/CLSID") } else { $regPaths=@('HKCU:Software/Classes/WOW6432Node/CLSID',"Registry::HKEY_USERS/$sid/Software/Classes/Wow6432Node/CLSID") }
    if ($DebugMode) { Log-UI "DEBUG: Registry paths to process: $($regPaths -join ', ')" }
    $finalValues = @(); $processedKeys = 0
    foreach ($regPath in $regPaths) { if (($regPath -match "HKEY_USERS") -and ($HKCUsync)) { if ($DebugMode) { Log-UI "DEBUG: Skipping HKU path due to HKCU sync: $regPath" }; continue }; if (-not $Silent) { Write-Host "Searching IDM CLSID Registry Keys in $regPath" }; if ($DebugMode) { Log-UI "DEBUG: Processing registry path: $regPath" }; $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue -ErrorVariable lockedKeys | Where-Object { $_.PSChildName -match '^{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}}$' }; foreach ($lockedKey in $lockedKeys) { $leafValue = Split-Path -Path $lockedKey.TargetObject -Leaf; $finalValues += $leafValue; if (-not $Silent) { Write-Output "$leafValue - Found Locked Key" }; if ($DebugMode) { Log-UI "DEBUG: Found locked key: $leafValue" }; if ($Force -or $ForceDelete) { try { if ($DebugMode) { Log-UI "DEBUG: Force mode - attempting to process locked key: $leafValue" }; $keyPath = "$regPath\$leafValue"; if (Test-Path $keyPath) { $acl = Get-Acl -Path $keyPath -ErrorAction SilentlyContinue; if ($acl) { $acl.SetOwner([System.Security.Principal.NTAccount]::new('Administrators')); $rule = New-Object System.Security.AccessControl.RegistryAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.SetAccessRule($rule); Set-Acl -Path $keyPath -AclObject $acl -ErrorAction SilentlyContinue; if ($DebugMode) { Log-UI "DEBUG: Force mode - unlocked key: $leafValue" } } } } catch { if ($DebugMode) { Log-UI "DEBUG: Force mode failed to unlock key $leafValue - $($_.Exception.Message)" } } } }; if ($subKeys -ne $null) { if ($DebugMode) { Log-UI "DEBUG: Found $($subKeys.Count) potential CLSID keys" }; $subKeysToExclude = "LocalServer32", "InProcServer32", "InProcHandler32"; $filteredKeys = $subKeys | Where-Object { !($_.GetSubKeyNames() | Where-Object { $subKeysToExclude -contains $_ }) }; if ($DebugMode) { Log-UI "DEBUG: After filtering: $($filteredKeys.Count) keys to analyze" }; foreach ($key in $filteredKeys) { $processedKeys++; $fullPath = $key.PSPath; $keyValues = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue; $defaultValue = $keyValues.PSObject.Properties | Where-Object { $_.Name -eq '(default)' } | Select-Object -ExpandProperty Value; if (($defaultValue -match "^\d+$") -and ($key.SubKeyCount -eq 0)) { $finalValues += $($key.PSChildName); if (-not $Silent) { Write-Output "$($key.PSChildName) - Found Digit In Default and No Subkeys" }; if ($DebugMode) { Log-UI "DEBUG: Matched rule 1 (digit in default): $($key.PSChildName)" }; continue }; if (($defaultValue -match "\+|=") -and ($key.SubKeyCount -eq 0)) { $finalValues += $($key.PSChildName); if (-not $Silent) { Write-Output "$($key.PSChildName) - Found + or = In Default and No Subkeys" }; if ($DebugMode) { Log-UI "DEBUG: Matched rule 2 (+/= in default): $($key.PSChildName)" }; continue }; $versionValue = Get-ItemProperty -Path "$fullPath\Version" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty '(default)' -ErrorAction SilentlyContinue; if (($versionValue -match "^\d+$") -and ($key.SubKeyCount -eq 1)) { $finalValues += $($key.PSChildName); if (-not $Silent) { Write-Output "$($key.PSChildName) - Found Digit In \Version and No Other Subkeys" }; if ($DebugMode) { Log-UI "DEBUG: Matched rule 3 (digit in version): $($key.PSChildName)" }; continue }; $keyValues.PSObject.Properties | ForEach-Object { if ($_.Name -match "MData|Model|scansk|Therad") { $finalValues += $($key.PSChildName); if (-not $Silent) { Write-Output "$($key.PSChildName) - Found MData Model scansk Therad" }; if ($DebugMode) { Log-UI "DEBUG: Matched rule 4 (IDM-specific values): $($key.PSChildName)" }; return } }; if (($key.ValueCount -eq 0) -and ($key.SubKeyCount -eq 0)) { $finalValues += $($key.PSChildName); if (-not $Silent) { Write-Output "$($key.PSChildName) - Found Empty Key" }; if ($DebugMode) { Log-UI "DEBUG: Matched rule 5 (empty key): $($key.PSChildName)" }; continue } } } }
    $finalValues = @($finalValues | Select-Object -Unique)
    if ($DebugMode) { Log-UI "DEBUG: Processed $processedKeys keys total"; Log-UI "DEBUG: Found $($finalValues.Count) unique IDM CLSID keys: $($finalValues -join ', ')" }
    if ($finalValues -ne $null) { if ($Delete) { if (-not $Silent) { Write-Host ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_msg1))) }; if ($DebugMode) { Log-UI "DEBUG: Starting deletion process for $($finalValues.Count) keys" } } else { if (-not $Silent) { Write-Host ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_msg2))) }; if ($DebugMode) { Log-UI "DEBUG: Starting locking process for $($finalValues.Count) keys" } } } else { if (-not $Silent) { Write-Host ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_msg3))) }; if ($DebugMode) { Log-UI "DEBUG: No IDM CLSID keys found to process" }; return }
    foreach ($regPath in $regPaths){ if (($regPath -match "HKEY_USERS") -and ($HKCUsync)) { continue }; foreach($id in $finalValues){ $full="$regPath/$id"; try { if ($Delete) { if (Test-Path $full){ $acl=Get-Acl -Path $full -ErrorAction SilentlyContinue; if ($acl){ $acl.SetOwner([System.Security.Principal.NTAccount]::new('Administrators')); $rule=New-Object System.Security.AccessControl.RegistryAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.SetAccessRule($rule); Set-Acl -Path $full -AclObject $acl -ErrorAction SilentlyContinue }; Remove-Item -Path $full -Recurse -Force -ErrorAction SilentlyContinue } } else { if (Test-Path $full){ $acl=Get-Acl -Path $full -ErrorAction SilentlyContinue; if ($acl){ $acl.SetAccessRuleProtection($true,$false); $deny=New-Object System.Security.AccessControl.RegistryAccessRule('Everyone','FullControl','ContainerInherit,ObjectInherit','None','Deny'); $acl.SetAccessRule($deny); Set-Acl -Path $full -AclObject $acl -ErrorAction SilentlyContinue } } } } catch {} }; if ($Delete){ try { if (Test-Path $regPath){ Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object { try { Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue } catch {} } } } catch {} } }
}
function Get-MachineGuid { try { (Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction SilentlyContinue).MachineGuid } catch { $null } }
function Get-Sha256Hex([string]$text){ try { $sha=[System.Security.Cryptography.SHA256]::Create(); $bytes=[System.Text.Encoding]::UTF8.GetBytes($text); $hash=$sha.ComputeHash($bytes); -join ($hash | ForEach-Object { $_.ToString('x2') }) } catch { '0000000000' } }

function Invoke-IDMOperation {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('activate','reset')]
        [string]$Mode,
        
        [switch]$Silent,
        [switch]$Force,
        [switch]$DebugMode
    )
    
    # Debug logging: Start function
    if ($DebugMode) { 
        Log-UI "DEBUG: Starting Invoke-IDMOperation (Mode=$Mode, Silent=$Silent, Force=$Force, DebugMode=$DebugMode)"
    }
    
    $result=@{Success=$false;Message=''}
    
    # Administrator check
    if (-not (Test-IsAdministrator)) { 
        $result.Message='Administrator privileges required.'
        if ($DebugMode) { Log-UI "DEBUG: Administrator check failed" }
        elseif (-not $Silent) { Log-UI "Error: Administrator privileges required" }
        return $result 
    }
    
    try {
        if ($DebugMode) { Log-UI "DEBUG: Administrator check passed" }
        
        Log-UI "Mode=$Mode"
        if ($Mode -in 'activate'){
            $idm=Get-IDMPath
            if ($DebugMode) { Log-UI "DEBUG: IDM path detected: $idm" }
            else { Log-UI "IDM path=$idm" }
            
            if ([string]::IsNullOrWhiteSpace($idm) -or -not (Test-Path $idm)){ 
                $result.Message='IDM is not installed.'
                if ($DebugMode) { Log-UI "DEBUG: IDM installation check failed - Path: $idm" }
                return $result 
            }
            
            # Internet connectivity check (can be bypassed with Force)
            $hasInternet = Test-InternetConnectivity
            if ($DebugMode) { Log-UI "DEBUG: Internet connectivity test result: $hasInternet" }
            
            if (-not $hasInternet) { 
                if ($Force) {
                    if ($DebugMode) { Log-UI "DEBUG: Force mode - bypassing internet connectivity requirement" }
                    elseif (-not $Silent) { Log-UI "Warning: No internet connectivity, but continuing due to Force mode" }
                } else {
                    $result.Message='No internet connectivity.'
                    if ($DebugMode) { Log-UI "DEBUG: Internet connectivity check failed" }
                    return $result 
                }
            } else {
                if ($DebugMode) { Log-UI "DEBUG: Internet connectivity confirmed" }
            }
        }
        
        Log-UI 'Stopping IDM process'
        if ($DebugMode) { Log-UI "DEBUG: Calling Stop-IDMProcess" }
        Stop-IDMProcess
        
        Log-UI 'Exporting registry backup'
        if ($DebugMode) { Log-UI "DEBUG: Calling Export-RegistryBackup" }
        Export-RegistryBackup
        
        Log-UI 'Removing IDM registry keys'
        if ($DebugMode) { Log-UI "DEBUG: Calling Remove-IDMRegistryKeys with flags" }
        Remove-IDMRegistryKeys -Silent:$Silent -Force:$Force -DebugMode:$DebugMode
        
        Log-UI 'Adding required registry keys'
        if ($DebugMode) { Log-UI "DEBUG: Calling Add-RequiredRegistryKeys" }
        Add-RequiredRegistryKeys -Silent:$Silent -Force:$Force -DebugMode:$DebugMode
        
        if ($Mode -eq 'reset') {
            Log-UI 'CLSID: delete+unlock'
            if ($DebugMode) { Log-UI "DEBUG: Reset mode - calling CLSID processing for delete+unlock" }
            Invoke-CLSIDProcessing -Delete $true -ForceDelete $true -Silent:$Silent -Force:$Force -DebugMode:$DebugMode
            Add-RequiredRegistryKeys -Silent:$Silent -Force:$Force -DebugMode:$DebugMode
            $result.Success=$true
            $result.Message='Reset completed.'
			
			# CLSID Registry Keys (HKCU ve HKLM)
		$clsids = @(
			"HKCU:\Software\Classes\Wow6432Node\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}",
			"HKCU:\Software\Classes\Wow6432Node\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}",
			"HKLM:\Software\Classes\Wow6432Node\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}",
			"HKLM:\Software\Classes\Wow6432Node\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}",
			"HKCU:\Software\Classes\CLSID\{7B8E9164-324D-4A2E-A46D-0165FB2000EC}",
			"HKCU:\Software\Classes\CLSID\{5ED60779-4DE2-4E07-B862-974CA4FF2E9C}",
			"HKCU:\Software\Classes\CLSID\{07999AC3-058B-40BF-984F-69EB1E554CA7}",
			"HKCU:\Software\Classes\CLSID\{6DDF00DB-1234-46EC-8356-27E7B2051192}",
			"HKCU:\Software\Classes\CLSID\{D5B91409-A8CA-4973-9A0B-59F713D25671}"
		)

		foreach ($clsid in $clsids) {
			if (Test-Path $clsid) {
				Remove-Item $clsid -Recurse -Force
				Write-Host "Deleted: $clsid"
			}
		}

		# Internet Download Manager keys
		$idmKeys = @(
			"HKLM:\SOFTWARE\Internet Download Manager",
			"HKLM:\SOFTWARE\Wow6432Node\Internet Download Manager"
		)

		foreach ($key in $idmKeys) {
			if (Test-Path $key) {
				Remove-Item $key -Recurse -Force
				Write-Host "Deleted: $key"
			}
		}

		# DownloadManager values (HKCU)
		$dmPropsHKCU = @("CheckUpdtVM","scansk","tvfrdt","FName","LName","Email","Serial")
		$dmHKCU = "HKCU:\Software\DownloadManager"

		foreach ($prop in $dmPropsHKCU) {
			if (Test-Path $dmHKCU) {
				Remove-ItemProperty -Path $dmHKCU -Name $prop -ErrorAction SilentlyContinue
				Write-Host "Deleted property: $prop from $dmHKCU"
			}
		}

		# DownloadManager values (specific HKU user)
		$dmHKU = "HKU:\S-1-5-21-2754736582-2265559669-3571272114-1001\Software\DownloadManager"
		foreach ($prop in @("FName","LName","Email","Serial")) {
			if (Test-Path $dmHKU) {
				Remove-ItemProperty -Path $dmHKU -Name $prop -ErrorAction SilentlyContinue
				Write-Host "Deleted property: $prop from $dmHKU"
			}
		}
		
		if ($DebugMode) { Log-UI "DEBUG: Reset operation completed successfully" }
        } else {
            Log-UI 'CLSID: delete (prep)'
            if ($DebugMode) { Log-UI "DEBUG: $Mode mode - calling CLSID processing for preparation" }
            Invoke-CLSIDProcessing -Delete $true -ForceDelete $false -Silent:$Silent -Force:$Force -DebugMode:$DebugMode
            
                if ($Mode -eq 'activate') {
                        # Sessiz mod deðilse ve isim cache'te yoksa þimdi sor
                        # Her aktivasyon denemesinde ismi tekrar sorabilmek için cache'i temizle
                        $script:LicenseOwner = $null
                        $name = Get-LicenseOwnerName -Silent:$Silent

                        Log-UI 'Register-IDM'
                        Register-IDM -LicenseName $name
                }
                        
            Log-UI 'CLSID: lock'
            if ($DebugMode) { Log-UI "DEBUG: $Mode mode - calling CLSID processing for locking" }
            Invoke-CLSIDProcessing -Delete $false -ForceDelete $false -Silent:$Silent -Force:$Force -DebugMode:$DebugMode
            
            $result.Success=$true
            $result.Message='Activation completed'
            if ($DebugMode) { Log-UI "DEBUG: $Mode operation completed successfully" }
        }
    } catch {
        $result.Message=$_.Exception.Message
        if ($DebugMode) { 
            Log-UI "DEBUG: Exception caught in Invoke-IDMOperation: $($_.Exception.Message)"
            Log-UI "DEBUG: Stack trace: $($_.ScriptStackTrace)"
        } else {
            Log-UI ("Caught exception: " + $_.Exception.Message)
        }
    }
    
    if ($DebugMode) { 
        Log-UI "DEBUG: Invoke-IDMOperation ending - Success: $($result.Success), Message: $($result.Message)"
    }
    
    return $result
}

# Command line execution logic (moved after function definitions)
if ($args.Count -gt 0 -or $silent -or $activate -or $reset -or $help -or $version -or $DebugMode) {
    Write-Host "DEBUG: Parameters detected! Running command line mode..." -ForegroundColor Green
    # Set script variables for UI logging
    $script:EnableUiDebug = $DebugMode
    
    if ($help) {
        Write-Host "IDM Tool" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Usage:" -ForegroundColor Yellow
        Write-Host "  IDMTool.ps1 [-activate|-reset] [-silent] [-force] [-debug]" 
        Write-Host "  IDMTool.ps1 [-help|-version]"
        Write-Host ""
        Write-Host "Actions:" -ForegroundColor Yellow
        Write-Host "  -activate    Activate IDM with registration"
        Write-Host "  -reset       Reset IDM to clean state"
        Write-Host ""
        Write-Host "Options:" -ForegroundColor Yellow
        Write-Host "  -silent      Run without user interaction"
        Write-Host "  -force       Force operation even if conditions not met"
        Write-Host "  -debug       Enable debug logging"
        Write-Host "  -help        Show this help message"
        Write-Host "  -version     Show version information"
        exit 0
    }
    
    if ($version) {
        Write-Host "IDM Tool" -ForegroundColor Cyan
        Write-Host "v1" -ForegroundColor Gray
        exit 0
    }
    
    # Determine operation mode
    if ($activate) { $mode = 'activate' }
    elseif ($reset) { $mode = 'reset' }
    
    Write-Host "IDM Tool | made by Abdullah ERTÜRK" -ForegroundColor Cyan
    Write-Host "Starting $mode operation..." -ForegroundColor Yellow
    if ($silent) { Write-Host "Running in silent mode" -ForegroundColor Gray }
    if ($force) { Write-Host "Force mode enabled" -ForegroundColor Gray }
    if ($DebugMode) { Write-Host "Debug logging enabled" -ForegroundColor Gray }
    
    # Execute the operation
    try {
        $result = Invoke-IDMOperation -Mode $mode -Silent:$silent -Force:$force -DebugMode:$DebugMode
        
        if ($result.Success) {
            Write-Host "SUCCESS: $($result.Message)" -ForegroundColor Green
            if (-not $silent) {
                Write-Host "Operation completed successfully." -ForegroundColor Green
            }
            exit 0
        } else {
            Write-Host "FAILED: $($result.Message)" -ForegroundColor Red
            if (-not $silent) {
                Write-Host "Operation failed. Check the error message above." -ForegroundColor Red
            }
            exit 1
        }
    } catch {
        Write-Host "EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
        if ($DebugMode) {
            Write-Host "Stack trace:" -ForegroundColor Gray
            Write-Host $_.ScriptStackTrace -ForegroundColor Gray
        }
        exit 1
    }
}

# GUI Form Creation and Setup
$form = New-Object System.Windows.Forms.Form
$form.Text = 'IDM Tool | made by Abdullah ERTÜRK'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object System.Drawing.Size(500, 300)
$form.TopMost = $false


$lblAction = New-Object System.Windows.Forms.Label
$lblAction.Text = 'Method'
$lblAction.AutoSize = $true
$lblAction.Location = New-Object System.Drawing.Point(12, 14)

$cbAction = New-Object System.Windows.Forms.ComboBox
$cbAction.DropDownStyle = 'DropDownList'
$cbAction.Location = New-Object System.Drawing.Point(80, 10)
$cbAction.Size = New-Object System.Drawing.Size(100, 24)
[void]$cbAction.Items.AddRange(@('activate','reset'))

$cbAction.SelectedIndex = 0

# ComboBox custom drawing for dark theme
$cbAction.Add_DrawItem({
    param($sender, $e)
    
    $backgroundColor = if ($global:isDarkTheme) { 
        [System.Drawing.Color]::FromArgb(60, 60, 60) 
    } else { 
        [System.Drawing.Color]::FromArgb(200, 200, 200) 
    }
    
    $textColor = if ($global:isDarkTheme) { 
        [System.Drawing.Color]::FromArgb(200, 200, 200) 
    } else { 
        [System.Drawing.Color]::Black 
    }
    
    # Fill entire background including borders
    $brush = New-Object System.Drawing.SolidBrush($backgroundColor)
    $e.Graphics.FillRectangle($brush, $e.Bounds)
    
    # Handle selection highlighting
    if (($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -eq [System.Windows.Forms.DrawItemState]::Selected) {
        $selectionColor = if ($global:isDarkTheme) { 
            [System.Drawing.Color]::FromArgb(90, 90, 90) 
        } else { 
            [System.Drawing.Color]::LightBlue 
        }
        $selectionBrush = New-Object System.Drawing.SolidBrush($selectionColor)
        $e.Graphics.FillRectangle($selectionBrush, $e.Bounds)
        $selectionBrush.Dispose()
    }
    
    # Draw text if item exists
    if ($e.Index -ge 0) {
        $text = $sender.Items[$e.Index].ToString()
        $textBrush = New-Object System.Drawing.SolidBrush($textColor)
        $e.Graphics.DrawString($text, $sender.Font, $textBrush, $e.Bounds.Left + 3, $e.Bounds.Top + 2)
        $textBrush.Dispose()
    }
    
    $brush.Dispose()
})

# Handle dropdown opening to ensure background
$cbAction.Add_DropDown({
    if ($global:isDarkTheme) {
        $cbAction.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
        $cbAction.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    }
})

$panelFlags = New-Object System.Windows.Forms.FlowLayoutPanel
$panelFlags.AutoSize = $true
$panelFlags.AutoSizeMode = 'GrowAndShrink'
$panelFlags.WrapContents = $false
$panelFlags.FlowDirection = 'LeftToRight'
$panelFlags.Anchor = 'Top,Right'

$chkSilent = New-Object System.Windows.Forms.CheckBox
$chkSilent.Text = '-silent'
$chkSilent.AutoSize = $true
$chkSilent.Margin = New-Object System.Windows.Forms.Padding(0,3,10,0)

$chkForce = New-Object System.Windows.Forms.CheckBox
$chkForce.Text = '-force'
$chkForce.AutoSize = $true
$chkForce.Margin = New-Object System.Windows.Forms.Padding(0,3,10,0)
$chkForce.Checked = $true

$chkDebug = New-Object System.Windows.Forms.CheckBox
$chkDebug.Text = '-debug'
$chkDebug.AutoSize = $true
$chkDebug.Margin = New-Object System.Windows.Forms.Padding(0,3,0,0)

[void]$panelFlags.Controls.AddRange(@($chkSilent,$chkForce,$chkDebug))

function Adjust-FlagsPanel { $panelFlags.Location = New-Object System.Drawing.Point(($form.ClientSize.Width - $panelFlags.PreferredSize.Width - 15), 8) }

function Toggle-DebugWindow {
    if ($chkDebug.Checked) {
        $form.ClientSize = New-Object System.Drawing.Size(500, 340)
        
        $btnPatch.Location = New-Object System.Drawing.Point(366, 195)
        
        $lblDebug.Location = New-Object System.Drawing.Point(15, 225)
        $tbDebugOutput.Location = New-Object System.Drawing.Point(15, 243)
        $tbDebugOutput.Size = New-Object System.Drawing.Size(470, 70)
        
        $lblDebug.Visible = $true
        $tbDebugOutput.Visible = $true
        $script:EnableUiDebug = $true
    } else {
        $form.ClientSize = New-Object System.Drawing.Size(500, 300)
        
        $btnPatch.Location = New-Object System.Drawing.Point(366, 195)
        
        $lblDebug.Visible = $false
        $tbDebugOutput.Visible = $false
        $script:EnableUiDebug = $false
        $tbDebugOutput.Clear()
    }
}

$lblPreview = New-Object System.Windows.Forms.Label
$lblPreview.Text = 'Command Preview'
$lblPreview.AutoSize = $true
$lblPreview.Location = New-Object System.Drawing.Point(12, 45)

$tbPreview = New-Object System.Windows.Forms.RichTextBox
$tbPreview.Location = New-Object System.Drawing.Point(15, 63)
$tbPreview.Size = New-Object System.Drawing.Size(470, 80)
$tbPreview.ReadOnly = $true
$tbPreview.BorderStyle = 'Fixed3D'
$tbPreview.Font = New-Object System.Drawing.Font('Consolas', 9)
$tbPreview.WordWrap = $false
$tbPreview.ScrollBars = 'Both'

$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Text = 'Ready'
$lblProgress.AutoSize = $false
$lblProgress.Height = 20
$lblProgress.Location = New-Object System.Drawing.Point(15, 149)
$lblProgress.Size = New-Object System.Drawing.Size(470, 20)
$lblProgress.TextAlign = 'MiddleLeft'

$progressBar = New-Object CustomControls.V2.SegmentedProgressBarV2
$progressBar.Location = New-Object System.Drawing.Point(15, 167)
$progressBar.Size = New-Object System.Drawing.Size(470, 24)
$progressBar.SegmentCount = 40
$progressBar.ShowPercentageText = $false
$progressBar.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
$progressBar.ForeColor = [System.Drawing.Color]::FromArgb(90,90,90)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Value = 0

$btnPatch = New-Object System.Windows.Forms.Button
$btnPatch.Text = 'Start Patching'
$btnPatch.Location = New-Object System.Drawing.Point(366, 195)
$btnPatch.Size = New-Object System.Drawing.Size(120, 30)
$btnPatch.Anchor = 'Top,Right'
$btnPatch.Enabled = $false
$lblDebug = New-Object System.Windows.Forms.Label
$lblDebug.Text = 'Debug Output'
$lblDebug.AutoSize = $true
$lblDebug.Location = New-Object System.Drawing.Point(15, 300)
$lblDebug.Visible = $true

$tbDebugOutput = New-Object System.Windows.Forms.RichTextBox
$tbDebugOutput.Location = New-Object System.Drawing.Point(15, 303)
$tbDebugOutput.Size = New-Object System.Drawing.Size(470, 70)
$tbDebugOutput.ReadOnly = $true
$tbDebugOutput.BorderStyle = 'Fixed3D'
$tbDebugOutput.Font = New-Object System.Drawing.Font('Consolas', 9)
$tbDebugOutput.WordWrap = $true
$tbDebugOutput.ScrollBars = 'Both'
$tbDebugOutput.BackColor = [System.Drawing.Color]::Black
$tbDebugOutput.ForeColor = [System.Drawing.Color]::LimeGreen
$tbDebugOutput.Visible = $true

$updatePreview = {
    $exe = 'IDMTool'
    $parts = @($exe)
    $action = [string]$cbAction.SelectedItem
    switch ($action) {
        'debug'   { $parts += '-debug' }
        default   {
            if ($chkSilent.Checked) { $parts += '-silent' }

            switch ($action) {
                'activate' { $parts += '-activate'; if ($chkForce.Checked) { $parts += '-force' } }
                'reset'    { $parts += '-reset' }
            }
            
            if ($chkDebug.Checked) { $parts += '-debug' }
        }
    }
    $tbPreview.Text = ($parts -join ' ')
    
    # Enable/disable Patching Start button based on action selection
    $btnPatch.Enabled = ![string]::IsNullOrEmpty($action) -and $action -ne ''
}

$cbAction.Add_SelectedIndexChanged({ & $updatePreview })
$chkSilent.Add_CheckedChanged({ & $updatePreview })
$chkForce.Add_CheckedChanged({ & $updatePreview })
$chkDebug.Add_CheckedChanged({ 
    & $updatePreview
    Toggle-DebugWindow
})
$btnPatch.Add_Click({
    # Clear command preview at start of operation
    if ($tbPreview -and -not $tbPreview.IsDisposed) {
        $tbPreview.Clear()
    }
    
    $actionNow = [string]$cbAction.SelectedItem
    $silent=$chkSilent.Checked; $force=$chkForce.Checked; $debug=$chkDebug.Checked
    $op = switch ($actionNow) { 'activate'{'activate'} 'reset'{'reset'} 'debug'{'activate'} default{'activate'} }
    $debugMode = ($actionNow -eq 'debug') -or $debug
    Log-UI "Started operation: $op (silent=$silent, force=$force, debug=$debug)"
    $lblProgress.Text = "Working Method: $op "; $progressBar.Value = 20
    try {
        $res = Invoke-IDMOperation -Mode $op -Silent:$silent -Force:$force -DebugMode:$debugMode
        Log-UI ("Invoke-IDMOperation returned: " + ($res | ConvertTo-Json -Compress))
        if ($res.Success) { 
            $progressBar.Value = 100; $lblProgress.Text = " $($res.Message)"; Log-UI "Completed successfully"
            # Scroll to top to see all logs from beginning
            if ($tbPreview -and -not $tbPreview.IsDisposed) {
                $tbPreview.SelectionStart = 0
                $tbPreview.ScrollToCaret()
            }
        }
        else { $progressBar.Value = 0; $lblProgress.Text = "Error: $($res.Message)"; Log-UI ("Failed: " + $res.Message); [System.Windows.Forms.MessageBox]::Show($res.Message,'Operation Failed',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) }
    } catch {
        $progressBar.Value = 0; $lblProgress.Text = "Exception"; Log-UI ("Exception: " + $_.Exception.Message)
    }
})

$form.Controls.AddRange(@($lblAction,$cbAction,$panelFlags,$lblPreview,$tbPreview,$lblProgress,$progressBar,$btnPatch,$lblDebug,$tbDebugOutput))

# Status Strip (referans betikteki gibi)
$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusStrip.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$statusStrip.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
$statusStrip.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Ready"
$statusLabel.Spring = $true
$statusLabel.TextAlign = "MiddleLeft"

# Theme selector dropdown (referans betikteki gibi)
$themeDropDown = New-Object System.Windows.Forms.ToolStripDropDownButton
$themeDropDown.Text = "Change Theme"
$themeDropDown.ToolTipText = "Switch between Dark and Light themes"
$themeDropDown.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$themeDropDown.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$themeDropDown.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
$themeDropDown.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)

$darkThemeItem = New-Object System.Windows.Forms.ToolStripMenuItem
$darkThemeItem.Text = "Dark Theme"
$darkThemeItem.Checked = $false
$darkThemeItem.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$lightThemeItem = New-Object System.Windows.Forms.ToolStripMenuItem
$lightThemeItem.Text = "Light Theme"
$lightThemeItem.Checked = $true
$lightThemeItem.Font = New-Object System.Drawing.Font("Segoe UI", 9)

[void]$themeDropDown.DropDownItems.AddRange(@($darkThemeItem, $lightThemeItem))

# Theme colors from main.ps1
# Dark Theme (Black) - tamamen siyah tonlarý
$darkBack = [System.Drawing.Color]::FromArgb(60, 60, 60)
$darkFore = [System.Drawing.Color]::FromArgb(200, 200, 200)
$slateBorder = [System.Drawing.Color]::FromArgb(40, 40, 40)
$slateDark = [System.Drawing.Color]::FromArgb(20, 20, 20)
$slateLight = [System.Drawing.Color]::FromArgb(60, 60, 60)
$slateHover = [System.Drawing.Color]::FromArgb(30, 30, 30)

# Light Theme (Metal Gray-White) - birebir main.ps1'den
$lightBack = [System.Drawing.Color]::FromArgb(245, 245, 245)
$lightFore = [System.Drawing.Color]::FromArgb(40, 40, 40)
$metalBorder = [System.Drawing.Color]::FromArgb(120, 120, 120)
$metalDark = [System.Drawing.Color]::FromArgb(90, 90, 90)
$metalLight = [System.Drawing.Color]::FromArgb(200, 200, 200)
$metalHover = [System.Drawing.Color]::FromArgb(230, 230, 230)

# Light Theme (Metal Gray-White) - birebir main.ps1'den
$lightBack = [System.Drawing.Color]::FromArgb(245, 245, 245)
$lightFore = [System.Drawing.Color]::FromArgb(40, 40, 40)
$metalBorder = [System.Drawing.Color]::FromArgb(120, 120, 120)
$metalDark = [System.Drawing.Color]::FromArgb(90, 90, 90)
$metalLight = [System.Drawing.Color]::FromArgb(200, 200, 200)
$metalHover = [System.Drawing.Color]::FromArgb(230, 230, 230)

# Global theme variable
$global:isDarkTheme = $false

# Apply Dark Theme function
function Apply-DarkTheme {
    $form.BackColor = $darkBack
    $form.ForeColor = $darkFore
    $tbPreview.BackColor = [System.Drawing.Color]::FromArgb(0, 0, 0)
    $tbPreview.ForeColor = $darkFore
    $tbPreview.BorderStyle = 'None'
    $progressBar.BackColor = [System.Drawing.Color]::FromArgb(60, 70, 80)
    $progressBar.ForeColor = $slateDark
    $statusStrip.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $statusStrip.ForeColor = $darkFore
    $themeDropDown.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
    $themeDropDown.ForeColor = $darkFore
    $versionLabel.ForeColor = [System.Drawing.Color]::LightGray
    
    # Control borders and backgrounds
    $cbAction.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $cbAction.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $cbAction.FlatStyle = 'Flat'
    $cbAction.DrawMode = 'OwnerDrawFixed'
    $cbAction.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    # Checkboxes
    $chkSilent.BackColor = $darkBack
    $chkSilent.ForeColor = $darkFore
    $chkSilent.FlatStyle = 'Flat'
    $chkSilent.FlatAppearance.CheckedBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $chkForce.BackColor = $darkBack
    $chkForce.ForeColor = $darkFore
    $chkForce.FlatStyle = 'Flat'
    $chkForce.FlatAppearance.CheckedBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $chkDebug.BackColor = $darkBack
    $chkDebug.ForeColor = $darkFore
    $chkDebug.FlatStyle = 'Flat'
    $chkDebug.FlatAppearance.CheckedBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    
    # Buttons
    $btnPatch.BackColor = [System.Drawing.Color]::FromArgb(35, 40, 45)
    $btnPatch.ForeColor = $darkFore
    $btnPatch.FlatStyle = 'Flat'
    $btnPatch.FlatAppearance.BorderSize = 0
       
    # Labels
    $lblAction.ForeColor = $darkFore
    $lblPreview.ForeColor = $darkFore
    
    # Debug controls
    $lblDebug.ForeColor = $darkFore
    $tbDebugOutput.BackColor = [System.Drawing.Color]::Black
    $tbDebugOutput.ForeColor = [System.Drawing.Color]::LimeGreen
    $tbDebugOutput.BorderStyle = 'None'
    
    # Progress controls
    $lblProgress.ForeColor = $darkFore
    $progressBar.BackColor = [System.Drawing.Color]::FromArgb(60, 70, 80)
    $progressBar.ForeColor = $slateDark
    
    # Force refresh all controls
    $cbAction.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $cbAction.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $cbAction.Refresh()
    $cbAction.Invalidate()
    $form.Refresh()
}

# Apply Light Theme function
function Apply-LightTheme {
    $form.BackColor = $lightBack
    $form.ForeColor = $lightFore
    $tbPreview.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $tbPreview.ForeColor = $lightFore
    $tbPreview.BorderStyle = 'Fixed3D'
    $progressBar.BackColor = $metalLight
    $progressBar.ForeColor = $metalDark
    $statusStrip.BackColor = $metalLight
    $statusStrip.ForeColor = $lightFore
    $themeDropDown.BackColor = [System.Drawing.Color]::FromArgb(235, 235, 235)
    $themeDropDown.ForeColor = $lightFore
    $versionLabel.ForeColor = [System.Drawing.Color]::Gray
    
    # Control borders and backgrounds
    $cbAction.BackColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $cbAction.ForeColor = $lightFore
    $cbAction.FlatStyle = 'Standard'
    $cbAction.DrawMode = 'Normal'
    
    # Checkboxes
    $chkSilent.BackColor = $lightBack
    $chkSilent.ForeColor = $lightFore
    $chkSilent.FlatStyle = 'Flat'
    $chkSilent.FlatAppearance.CheckedBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $chkForce.BackColor = $lightBack
    $chkForce.ForeColor = $lightFore
    $chkForce.FlatStyle = 'Flat'
    $chkForce.FlatAppearance.CheckedBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $chkDebug.BackColor = $lightBack
    $chkDebug.ForeColor = $lightFore
    $chkDebug.FlatStyle = 'Flat'
    $chkDebug.FlatAppearance.CheckedBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    
    # Buttons
    $btnPatch.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $btnPatch.ForeColor = $lightFore
    $btnPatch.FlatStyle = 'Standard'

    
    # Labels
    $lblAction.ForeColor = $lightFore
    $lblPreview.ForeColor = $lightFore
    
    # Debug controls
    $lblDebug.ForeColor = $lightFore
    $tbDebugOutput.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $tbDebugOutput.ForeColor = $lightFore
    $tbDebugOutput.BorderStyle = 'Fixed3D'
    
    # Progress controls
    $lblProgress.ForeColor = $lightFore
    $progressBar.BackColor = $metalLight
    $progressBar.ForeColor = $metalDark
    
    # Force refresh ComboBox for light theme
    $cbAction.BackColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $cbAction.ForeColor = $lightFore
    $cbAction.Refresh()
    $cbAction.Invalidate()
}

# Theme switching functionality
$darkThemeItem.Add_Click({
    $darkThemeItem.Checked = $true
    $lightThemeItem.Checked = $false
    if (-not $global:isDarkTheme) {
        Apply-DarkTheme
        $global:isDarkTheme = $true
        $form.Refresh()
    }
})

$lightThemeItem.Add_Click({
    $lightThemeItem.Checked = $true
    $darkThemeItem.Checked = $false
    if ($global:isDarkTheme) {
        Apply-LightTheme
        $global:isDarkTheme = $false
        $form.Refresh()
    }
})

# Version label (referans betikteki gibi)
$versionLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$versionLabel.Text = "IDM Tool"
$versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$versionLabel.ForeColor = [System.Drawing.Color]::LightGray

# Separator between theme selector and version
$themeVersionSeparator = New-Object System.Windows.Forms.ToolStripSeparator
$themeVersionSeparator.Margin = New-Object System.Windows.Forms.Padding(5, 0, 5, 0)

[void]$statusStrip.Items.AddRange(@($statusLabel, $themeDropDown, $themeVersionSeparator, $versionLabel))

# Initialize with Light Theme
Apply-LightTheme

$form.Controls.Add($statusStrip)

$tooltip = New-Object System.Windows.Forms.ToolTip
$tooltip.AutoPopDelay = 5000
$tooltip.InitialDelay = 500
$tooltipVisible = $false

function Show-BoundedTooltip {
    param($control, $text)
    if ($tooltipVisible) { return }
    $tooltipVisible = $true
    
    # Special case for Patching Start button - use simple positioning
    if ($control -eq $btnPatch) {
        Show-PatchTooltip $control $text
        return
    }
    
    # Proper word-boundary text wrapping
    $words = $text -split ' '
    $lines = @()
    $currentLine = ''
    
    foreach ($word in $words) {
        if (($currentLine + ' ' + $word).Length -le 25) {
            if ($currentLine -eq '') {
                $currentLine = $word
            } else {
                $currentLine += ' ' + $word
            }
        } else {
            if ($currentLine -ne '') {
                $lines += $currentLine
            }
            $currentLine = $word
        }
    }
    if ($currentLine -ne '') {
        $lines += $currentLine
    }
    
    $wrappedText = $lines -join "`r`n"
    
    # Better height calculation
    $lineCount = $lines.Count
    if ($lineCount -eq 0) { $lineCount = 1 }
    $tooltipHeight = $lineCount * 22 + 25
    
    # Get actual control position on form
    if ($control.Parent -ne $null -and $control.Parent -ne $form) {
        # Control is in a panel, calculate real position
        $x = $control.Parent.Location.X + $control.Location.X
        $y = $control.Parent.Location.Y + $control.Location.Y
        $controlSize = $control.Size
    } else {
        # Control is directly on form
        $x = $control.Location.X
        $y = $control.Location.Y  
        $controlSize = $control.Size
    }
    
    # Special offset for interactive controls to avoid covering them
    $extraOffset = 0
    if ($control -eq $cbAction) {
        $extraOffset = 15  # Additional space to keep control visible
    }
    if ($control -eq $chkSilent -or $control -eq $chkForce -or $control -eq $chkDebug) {
        $extraOffset = 25  # Same offset for all checkboxes to align tooltips
    }
    
    # Determine if we should show above or below
    $showAbove = ($y + $controlSize.Height + $tooltipHeight + 10 + $extraOffset) -gt $form.ClientSize.Height
        
    if ($showAbove) {
        # Show above the control
        $tooltipY = $y - $tooltipHeight - 10 - $extraOffset
        if ($tooltipY -lt 0) { $tooltipY = 5 }
    } else {
        # Show below the control with extra offset
        $tooltipY = $y + $controlSize.Height + 10 + $extraOffset
    }
    
    # Keep X within form bounds
    $tooltipX = $x
    
    # Move checkbox tooltips to the right side of the form
    if ($control -eq $chkSilent -or $control -eq $chkForce -or $control -eq $chkDebug) {
        $tooltipX = 250  # Fixed position on the right side
    }
    
    # Ensure tooltip stays within bounds
    if ($tooltipX + 260 -gt $form.ClientSize.Width) {
        $tooltipX = $form.ClientSize.Width - 270
    }
    if ($tooltipX -lt 10) { $tooltipX = 10 }
    
    $tooltip.Show($wrappedText, $form, $tooltipX, $tooltipY, 5000)
}

function Show-PatchTooltip {
    param($control, $text)
    # Simple positioning for Patching Start button only
    $wrappedText = $text
    $tooltipY = $control.Location.Y - 10  # 10px above button
    $tooltipX = $control.Location.X - 150  # Move tooltip to left to stay within GUI bounds
    
    # Ensure tooltip stays within form boundaries
    if ($tooltipX -lt 10) { $tooltipX = 10 }
    if ($tooltipX + 250 -gt $form.ClientSize.Width) {
        $tooltipX = $form.ClientSize.Width - 260
    }
    
    $tooltip.Show($wrappedText, $form, $tooltipX, $tooltipY, 5000)
}

function Hide-BoundedTooltip {
    if (-not $tooltipVisible) { return }
    $tooltipVisible = $false
    $tooltip.Hide($form)
}

$btnPatch.Add_MouseEnter({ Show-BoundedTooltip $btnPatch "Start the process for the selected method." })
$chkSilent.Add_MouseEnter({ Show-BoundedTooltip $chkSilent "Run the process without showing progress messages. The license holder name defaults to the Windows username." })
$chkForce.Add_MouseEnter({ Show-BoundedTooltip $chkForce "Forced labor even if conditions are not met." })
$chkDebug.Add_MouseEnter({ Show-BoundedTooltip $chkDebug "Enable debug logging and show debug output window." })
$cbAction.Add_MouseEnter({ Show-BoundedTooltip $cbAction "Select process type" })

$btnPatch.Add_MouseLeave({ Hide-BoundedTooltip })
$chkSilent.Add_MouseLeave({ Hide-BoundedTooltip })
$chkForce.Add_MouseLeave({ Hide-BoundedTooltip })
$chkDebug.Add_MouseLeave({ Hide-BoundedTooltip })
$cbAction.Add_MouseLeave({ Hide-BoundedTooltip })

$form.Add_Shown({ Adjust-FlagsPanel })
$form.Add_Resize({ Adjust-FlagsPanel })

$btnDownloadIDM = New-Object System.Windows.Forms.Button
$btnDownloadIDM.Text = 'Download IDM'
$btnDownloadIDM.Location = New-Object System.Drawing.Point(15, 195)
$btnDownloadIDM.Size = New-Object System.Drawing.Size(120, 30)

$btnDownloadIDM.Add_Click({
    $progressBar.Value = 10
    $statusLabel.Text = "Receiving connection..."
    $url = "https://www.internetdownloadmanager.com/download.html"
    $html = Invoke-WebRequest -Uri $url -UseBasicParsing
    $downloadLink = ($html.Links | Where-Object { $_.class -eq "cta-btn" }).href

    if (-not $downloadLink) {
        [System.Windows.Forms.MessageBox]::Show("Download link not found.","Error")
        return
    }

    $progressBar.Value = 30
    $statusLabel.Text = "IDM is downloading..."
    $installerPath = "$env:TEMP\\idman_installer.exe"
    Invoke-WebRequest -Uri $downloadLink -OutFile $installerPath

    $progressBar.Value = 60
    $statusLabel.Text = "The process is ending..."
    Stop-AllIDMProcesses

    $progressBar.Value = 80
    $statusLabel.Text = "Starting the installation..."
    $statusLabel.Text = "Starting the installation (unattended)..."
    $res = Install-IDMUnattended -InstallerPath $installerPath -DebugMode:$debug
    if (-not $res.Success) {
        [System.Windows.Forms.MessageBox]::Show("Unattended installation failed. Please run the installation file manually.","Error")
        return
    }

    $progressBar.Value = 100
    $statusLabel.Text = "Installation completed."
    [System.Windows.Forms.MessageBox]::Show("IDM downloaded and installation completed.","Succes")
    $progressBar.Value = 0
    Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
})

$form.Controls.Add($btnDownloadIDM)

& $updatePreview
[void]$form.ShowDialog()