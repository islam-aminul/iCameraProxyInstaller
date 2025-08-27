#Requires -RunAsAdministrator

param([switch]$Uninstall)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Global variables
$script:Config = $null
$script:MainForm = $null
$script:ProgressBar = $null
$script:StatusLabel = $null
$script:LogDisplay = $null
$script:CurrentStep = 0
$script:Mutex = $null
$script:LogFile = $null
$script:InstallPath = $null
[int]$script:DatabasePort = 0
$script:InstallFileCatalyst = $false

# Logging functions
function Initialize-Logging
{
    $timestamp = Get-Date -Format "yyyyMMdd"
    $script:LogFile = Join-Path $PSScriptRoot "installer_$timestamp.log"

    Write-Log -Message "=== iCamera Proxy Installer Started ===" -Level "INFO"
    Write-Log -Message "Timestamp: $( Get-Date )" -Level "INFO"
    Write-Log -Message "Machine Name: $env:COMPUTERNAME" -Level "INFO"
    Write-Log -Message "User: $env:USERNAME" -Level "INFO"
    Write-Log -Message "OS: $( (Get-WmiObject Win32_OperatingSystem).Caption )" -Level "INFO"
    Write-Log -Message "PowerShell Version: $( $PSVersionTable.PSVersion )" -Level "INFO"
    Write-Log -Message "Script Path: $PSCommandPath" -Level "INFO"
    Write-Log -Message "Working Directory: $PWD" -Level "INFO"
}

function Add-LogDisplay
{
    param([System.Windows.Forms.Form]$Form)

    $logBox = New-Object System.Windows.Forms.RichTextBox
    $logBox.Location = New-Object System.Drawing.Point(20, 90)
    $logBox.Size = New-Object System.Drawing.Size(740, 420)
    $logBox.Anchor = "Top,Bottom,Left,Right"
    $logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $logBox.BackColor = [System.Drawing.Color]::Black
    $logBox.ReadOnly = $true
    $logBox.ScrollBars = "Vertical"

    $Form.Controls.Add($logBox)
    return $logBox
}

function Write-Log
{
    param([string]$Message, [ValidateSet("INFO", "WARNING", "ERROR")]$Level = "INFO")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to console
    switch ($Level)
    {
        "ERROR" {
            Write-Host $logEntry -ForegroundColor Red
        }
        "WARNING" {
            Write-Host $logEntry -ForegroundColor Yellow
        }
        "INFO" {
            Write-Host $logEntry -ForegroundColor Green
        }
    }

    # Write to GUI log display
    if ($script:LogDisplay)
    {
        $script:LogDisplay.Invoke([Action]{
            $color = switch ($Level)
            {
                "ERROR" {
                    [System.Drawing.Color]::Red
                }
                "WARNING" {
                    [System.Drawing.Color]::Yellow
                }
                "INFO" {
                    [System.Drawing.Color]::LightGreen
                }
            }

            $script:LogDisplay.SelectionStart = $script:LogDisplay.TextLength
            $script:LogDisplay.SelectionLength = 0
            $script:LogDisplay.SelectionColor = $color
            $script:LogDisplay.AppendText("$logEntry`n")
            $script:LogDisplay.ScrollToCaret()
        })
    }

    # Write to file
    if ($script:LogFile)
    {
        Add-Content -Path $script:LogFile -Value $logEntry -Encoding UTF8
    }
}

# Load configuration
function Get-Configuration
{
    param([string]$ConfigPath = ".\installer.config.json")

    Write-Log -Message "Loading configuration from: $ConfigPath" -Level "INFO"

    if (-not (Test-Path $ConfigPath))
    {
        $errorMsg = "Configuration file not found: $ConfigPath"
        Write-Log -Message $errorMsg -Level "ERROR"
        throw $errorMsg
    }

    Write-Log -Message "Configuration loaded successfully" -Level "INFO"
    return Get-Content $ConfigPath | ConvertFrom-Json
}

# Admin and instance checks
function Test-AdminRights
{
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-AdminElevation
{
    try
    {
        $scriptPath = $MyInvocation.ScriptName
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        exit 0
    }
    catch
    {
        Show-Error -Message "Administrative access was cancelled or failed. The installer cannot continue without administrator privileges."
        exit 1
    }
}

function Test-ExistingInstance
{
    $mutexName = "Global\iCameraProxyInstaller"
    $script:Mutex = New-Object System.Threading.Mutex($false, $mutexName)

    if (-not $script:Mutex.WaitOne(0))
    {
        $errorMsg = "Another instance of the installer is already running"
        Write-Log -Message $errorMsg -Level "ERROR"
        Show-Error -Message "$errorMsg. Please wait for it to complete or close it before running again."
        return $false
    }
    Write-Log -Message "Mutex acquired successfully" -Level "INFO"
    return $true
}

function Release-Mutex
{
    if ($script:Mutex)
    {
        $script:Mutex.ReleaseMutex()
        $script:Mutex.Dispose()
    }
}

# GUI Functions
function Initialize-MainWindow
{
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $script:Config.ui.windowTitle
    $form.Size = New-Object System.Drawing.Size(800, 600)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.MinimumSize = New-Object System.Drawing.Size(600, 400)

    return $form
}

function Add-ProgressBar
{
    param([System.Windows.Forms.Form]$Form)

    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(20, 20)
    $progressBar.Size = New-Object System.Drawing.Size(740, 25)
    $progressBar.Anchor = "Top,Left,Right"
    $progressBar.Maximum = $script:Config.installation.totalSteps
    $progressBar.Value = 0

    $Form.Controls.Add($progressBar)
    return $progressBar
}

function Add-StatusLabel
{
    param([System.Windows.Forms.Form]$Form)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 55)
    $label.Size = New-Object System.Drawing.Size(740, 25)
    $label.Anchor = "Top,Left,Right"
    $label.Text = "Ready to begin installation..."
    $label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

    $Form.Controls.Add($label)
    return $label
}

function Update-Progress
{
    param([int]$Step, [string]$Message)

    $script:CurrentStep = $Step
    $script:ProgressBar.Value = $Step
    $script:StatusLabel.Text = $Message
    $script:StatusLabel.ForeColor = [System.Drawing.Color]::Black  # Reset to normal color
    $script:MainForm.Refresh()

    Write-Log -Message "Step $Step/$( $script:Config.installation.totalSteps ): $Message" -Level "INFO"
}

function Show-Message
{
    param([string]$Message, [string]$Title = "Information", [System.Windows.Forms.MessageBoxButtons]$Buttons = [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information)

    return [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
}

function Show-Error
{
    param([string]$Message, [string]$Title = "Error")

    Write-Log -Message $Message -Level "ERROR"

    # Update status label to show error in red with log file reference
    if ($script:StatusLabel)
    {
        $script:StatusLabel.ForeColor = [System.Drawing.Color]::Red
        $logFileName = if ($script:LogFile)
        {
            [System.IO.Path]::GetFileName($script:LogFile)
        }
        else
        {
            "installer.log"
        }
        $script:StatusLabel.Text = "ERROR: Installation failed. Check log: $logFileName"
        $script:MainForm.Refresh()
    }

    $result = Show-Message -Message $Message -Title $Title -Icon ([System.Windows.Forms.MessageBoxIcon]::Error)

    # Do not close main form on error - keep window open
}

function Show-Warning
{
    param([string]$Message, [string]$Title = "Warning")

    Write-Log -Message $Message -Level "WARNING"
    Show-Message -Message $Message -Title $Title -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
}

function Get-UserInput
{
    param([string]$Prompt, [string]$Title = "Input Required", [string]$DefaultValue = "")

    return [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, $Title, $DefaultValue)
}

# ACL permission function
function Set-DirectoryPermissions
{
    param([string]$Path)

    try
    {
        Write-Log -Message "Setting ACL permissions for: $Path" -Level "INFO"

        $acl = Get-Acl $Path
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $Path -AclObject $acl

        Write-Log -Message "ACL permissions set successfully for: $Path" -Level "INFO"
    }
    catch
    {
        Write-Log -Message "Failed to set ACL permissions for $Path`: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}

# Installation step functions
function Invoke-Step1
{
    Write-Log -Message "Starting Step 1: Prerequisites Check" -Level "INFO"
    Update-Progress -Step 1 -Message "Checking prerequisites..."
    Write-Log -Message "Prerequisites check completed" -Level "INFO"
}
function Invoke-Step2
{
    Write-Log -Message "Starting Step 2: Cleanup" -Level "INFO"
    Update-Progress -Step 2 -Message "Performing cleanup..."

    try
    {
        # Get scheduled task info
        $taskName = $script:Config.cleanup.taskName
        $folderName = $script:Config.cleanup.folderName

        Write-Log -Message "Looking for scheduled task: $taskName" -Level "INFO"

        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

        if ($task)
        {
            Write-Log -Message "Found scheduled task: $taskName" -Level "INFO"

            # Get task action to determine installation drive
            $taskAction = $task.Actions | Where-Object { $_.Execute -like "*.exe" -or $_.Execute -like "*.bat" -or $_.Execute -like "*.ps1" } | Select-Object -First 1

            if ($taskAction -and $taskAction.Execute)
            {
                $scriptPath = $taskAction.Execute
                Write-Log -Message "Task script path: $scriptPath" -Level "INFO"

                # Extract drive letter
                $driveLetter = [System.IO.Path]::GetPathRoot($scriptPath).TrimEnd('\\')
                Write-Log -Message "Determined installation drive: $driveLetter" -Level "INFO"

                # Construct folder path to delete
                $folderPath = Join-Path $driveLetter $folderName

                # Delete folder if exists
                if (Test-Path $folderPath)
                {
                    Write-Log -Message "Deleting folder: $folderPath" -Level "INFO"
                    Remove-Item -Path $folderPath -Recurse -Force
                    Write-Log -Message "Folder deleted successfully: $folderPath" -Level "INFO"
                }
                else
                {
                    Write-Log -Message "Folder not found: $folderPath" -Level "INFO"
                }
            }
            else
            {
                Write-Log -Message "Could not determine script path from task action" -Level "WARNING"
            }

            # Remove scheduled task
            Write-Log -Message "Removing scheduled task: $taskName" -Level "INFO"
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Log -Message "Scheduled task removed successfully: $taskName" -Level "INFO"

        }
        else
        {
            Write-Log -Message "Scheduled task not found: $taskName" -Level "INFO"
        }

        Write-Log -Message "Cleanup completed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "Cleanup failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
function Invoke-Step3
{
    Write-Log -Message "Starting Step 3: Drive Selection & Directory Creation" -Level "INFO"
    Update-Progress -Step 3 -Message "Selecting drive and creating directory..."

    try
    {
        # Get available drives
        $drives = @(Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 })
        Write-Log -Message "Found $( $drives.Count ) available drives" -Level "INFO"

        $selectedDrive = $null

        if ($drives.Count -eq 1)
        {
            # Only one drive available
            $selectedDrive = $drives[0].DeviceID
            Write-Log -Message "Single drive detected, auto-selecting: $selectedDrive" -Level "INFO"
        }
        else
        {
            # Multiple drives - prompt user with most free space as default
            $recommendedDrive = $drives | Sort-Object FreeSpace -Descending | Select-Object -First 1
            $driveList = $drives | ForEach-Object { "$( $_.DeviceID ) (Free: $([math]::Round($_.FreeSpace/1GB, 2) ) GB)" }

            Write-Log -Message "Multiple drives available: $( $driveList -join ', ' )" -Level "INFO"
            Write-Log -Message "Recommended drive (most free space): $( $recommendedDrive.DeviceID )" -Level "INFO"

            # Prompt user for drive selection
            $driveOptions = $drives | ForEach-Object { $_.DeviceID }
            $prompt = "Select installation drive:`n`n" + ($driveList -join "`n") + "`n`nRecommended: $( $recommendedDrive.DeviceID )"

            do
            {
                $userInput = Get-UserInput -Prompt $prompt -Title "Drive Selection" -DefaultValue $recommendedDrive.DeviceID

                if ( [string]::IsNullOrWhiteSpace($userInput))
                {
                    Write-Log -Message "User cancelled drive selection" -Level "WARNING"
                    throw "Drive selection cancelled by user"
                }

                $selectedDrive = $userInput.ToUpper().TrimEnd(':')
                if ($selectedDrive -notlike "*:")
                {
                    $selectedDrive += ":"
                }

                if ($selectedDrive -in $driveOptions)
                {
                    Write-Log -Message "User selected drive: $selectedDrive" -Level "INFO"
                    break
                }
                else
                {
                    Show-Warning -Message "Invalid drive selection. Please choose from available drives."
                }
            } while ($true)
        }

        # Create installation path
        $directoryName = $script:Config.installation.directoryName
        $script:InstallPath = Join-Path $selectedDrive $directoryName

        Write-Log -Message "Installation path: $script:InstallPath" -Level "INFO"

        # Create directory if it doesn't exist
        if (-not (Test-Path $script:InstallPath))
        {
            Write-Log -Message "Creating installation directory: $script:InstallPath" -Level "INFO"
            New-Item -Path $script:InstallPath -ItemType Directory -Force | Out-Null
            Write-Log -Message "Installation directory created successfully" -Level "INFO"
        }
        else
        {
            Write-Log -Message "Installation directory already exists: $script:InstallPath" -Level "INFO"
        }

        # Verify directory creation
        if (Test-Path $script:InstallPath)
        {
            Write-Log -Message "Directory verification successful: $script:InstallPath" -Level "INFO"

            # Set ACL permissions for installation root
            Set-DirectoryPermissions -Path $script:InstallPath
        }
        else
        {
            throw "Failed to create or verify installation directory: $script:InstallPath"
        }

        Write-Log -Message "Drive selection and directory creation completed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "Drive selection and directory creation failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
function Invoke-Step4
{
    Write-Log -Message "Starting Step 4: Prechecks" -Level "INFO"
    Update-Progress -Step 4 -Message "Performing system prechecks..."

    try
    {
        $requirements = $script:Config.requirements
        $preChecksPassed = $true

        # Check RAM
        Write-Log -Message "Checking system RAM requirements" -Level "INFO"
        $totalRamGB = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        $requiredRamGB = $requirements.minimumRamGB

        Write-Log -Message "Total RAM: $totalRamGB GB, Required: $requiredRamGB GB" -Level "INFO"

        if ($totalRamGB -lt $requiredRamGB)
        {
            $errorMsg = "Insufficient RAM: $totalRamGB GB available, $requiredRamGB GB required"
            Write-Log -Message $errorMsg -Level "ERROR"
            Show-Error -Message $errorMsg
            $preChecksPassed = $false
        }
        else
        {
            Write-Log -Message "RAM requirement satisfied" -Level "INFO"
        }

        # Check disk space on selected drive
        Write-Log -Message "Checking disk space requirements" -Level "INFO"
        $driveLetter = [System.IO.Path]::GetPathRoot($script:InstallPath).TrimEnd('\\')
        $drive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $driveLetter }
        $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
        $requiredSpaceGB = $requirements.minimumDiskSpaceGB

        Write-Log -Message "Free space on $driveLetter $freeSpaceGB GB, Required: $requiredSpaceGB GB" -Level "INFO"

        if ($freeSpaceGB -lt $requiredSpaceGB)
        {
            $errorMsg = "Insufficient disk space: $freeSpaceGB GB available, $requiredSpaceGB GB required on drive $driveLetter"
            Write-Log -Message $errorMsg -Level "ERROR"
            Show-Error -Message $errorMsg
            $preChecksPassed = $false
        }
        else
        {
            Write-Log -Message "Disk space requirement satisfied" -Level "INFO"
        }

        # Exit if system requirements not met
        if (-not $preChecksPassed)
        {
            Write-Log -Message "System requirements not met, exiting installation" -Level "ERROR"
            throw "System requirements verification failed"
        }

        # Check connectivity to required URLs
        Write-Log -Message "Checking connectivity to required URLs" -Level "INFO"
        $connectivityIssues = @()

        foreach ($url in $requirements.connectivityUrls)
        {
            Write-Log -Message "Testing connectivity to: $url" -Level "INFO"

            try
            {
                $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
                Write-Log -Message "Connectivity OK: $url (Status: $( $response.StatusCode ))" -Level "INFO"
            }
            catch
            {
                $warningMsg = "Connectivity failed: $url - $( $_.Exception.Message )"
                Write-Log -Message $warningMsg -Level "WARNING"
                $connectivityIssues += $url
            }
        }

        # Warn user about connectivity issues
        if ($connectivityIssues.Count -gt 0)
        {
            $warningMsg = "Connectivity issues detected with the following URLs:`n" + ($connectivityIssues -join "`n") + "`n`nThe installation can continue, but some features may not work properly."
            Write-Log -Message "Connectivity warnings: $( $connectivityIssues.Count ) URLs unreachable" -Level "WARNING"
            Show-Warning -Message $warningMsg
        }
        else
        {
            Write-Log -Message "All connectivity checks passed" -Level "INFO"
        }

        Write-Log -Message "Prechecks completed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "Prechecks failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
# Dependency management functions
function Find-LocalPackage
{
    param([string]$FilePattern, [string[]]$SearchFolders, [string[]]$SupportedExtensions)

    foreach ($folder in $SearchFolders)
    {
        $expandedFolder = [Environment]::ExpandEnvironmentVariables($folder)
        if (Test-Path $expandedFolder)
        {
            $patterns = $FilePattern -split ','
            foreach ($pattern in $patterns)
            {
                $files = Get-ChildItem -Path $expandedFolder -Filter $pattern.Trim() -ErrorAction SilentlyContinue
                foreach ($file in $files)
                {
                    if ($file.Extension -in $SupportedExtensions)
                    {
                        return $file.FullName
                    }
                }
            }
        }
    }
    return $null
}

function Test-FileLocked
{
    param([string]$FilePath)

    try
    {
        $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $fileStream.Close()
        return $false
    }
    catch
    {
        Write-Log -Message "File is locked: $FilePath" -Level "WARNING"
        return $true
    }
}

function Wait-ForFileUnlock
{
    param([string]$FilePath, [int]$TimeoutSeconds = 30)

    $timeout = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $timeout)
    {
        if (-not (Test-FileLocked -FilePath $FilePath))
        {
            return $true
        }
        Write-Log -Message "Waiting for file unlock: $FilePath" -Level "INFO"
        Start-Sleep -Seconds 2
    }
    return $false
}

function Get-FileHash256
{
    param([string]$FilePath)
    return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
}

function Test-FileIntegrity
{
    param([string]$FilePath, [string]$ExpectedSha256 = "")

    try
    {
        # Basic file existence and readability
        if (-not (Test-Path $FilePath))
        {
            Write-Log -Message "File not found: $FilePath" -Level "ERROR"
            return $false
        }

        # Check if file is locked
        if (Test-FileLocked -FilePath $FilePath)
        {
            Write-Log -Message "File is locked, waiting for unlock: $FilePath" -Level "WARNING"
            if (-not (Wait-ForFileUnlock -FilePath $FilePath))
            {
                Write-Log -Message "File unlock timeout: $FilePath" -Level "ERROR"
                return $false
            }
        }

        # File size validation (must be > 0)
        $fileInfo = Get-Item $FilePath
        if ($fileInfo.Length -eq 0)
        {
            Write-Log -Message "File is empty: $FilePath" -Level "ERROR"
            return $false
        }

        # SHA256 validation if provided
        if (-not [string]::IsNullOrEmpty($ExpectedSha256))
        {
            $actualHash = Get-FileHash256 -FilePath $FilePath
            if ($actualHash -ne $ExpectedSha256)
            {
                Write-Log -Message "SHA256 mismatch for $FilePath. Expected: $ExpectedSha256, Actual: $actualHash" -Level "ERROR"
                return $false
            }
            Write-Log -Message "SHA256 verification passed: $FilePath" -Level "INFO"
        }

        # File format validation for executables
        if ($FilePath -like "*.exe")
        {
            try
            {
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
                if ( [string]::IsNullOrEmpty($versionInfo.FileVersion))
                {
                    Write-Log -Message "Warning: Executable has no version info: $FilePath" -Level "WARNING"
                }
            }
            catch
            {
                Write-Log -Message "Warning: Could not read executable metadata: $FilePath" -Level "WARNING"
            }
        }

        # Archive validation for ZIP/7Z files
        if ($FilePath -like "*.zip")
        {
            try
            {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
                $entryCount = $archive.Entries.Count
                $archive.Dispose()

                if ($entryCount -eq 0)
                {
                    Write-Log -Message "ZIP archive is empty: $FilePath" -Level "ERROR"
                    return $false
                }
                Write-Log -Message "ZIP archive validated ($entryCount entries): $FilePath" -Level "INFO"
            }
            catch
            {
                Write-Log -Message "ZIP archive appears corrupted, will retry download: $FilePath" -Level "WARNING"
                # Delete corrupted file to force re-download
                Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
                return $false
            }
        }

        Write-Log -Message "File integrity validation passed: $FilePath" -Level "INFO"
        return $true

    }
    catch
    {
        Write-Log -Message "File integrity check failed: $FilePath - $( $_.Exception.Message )" -Level "ERROR"
        return $false
    }
}

function Download-Package
{
    param([string]$Url, [string]$DestinationPath, [int]$MaxRetries = 3)

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try
        {
            Write-Log -Message "Download attempt $attempt/$MaxRetries`: $Url" -Level "INFO"

            # Remove existing file if corrupted
            if (Test-Path $DestinationPath)
            {
                Remove-Item $DestinationPath -Force
            }

            Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing -TimeoutSec 120

            # Basic file size check
            $fileInfo = Get-Item $DestinationPath
            if ($fileInfo.Length -gt 1024)
            {
                # Must be > 1KB
                Write-Log -Message "Download completed: $( $fileInfo.Length ) bytes" -Level "INFO"
                return $true
            }
            else
            {
                Write-Log -Message "Downloaded file too small: $( $fileInfo.Length ) bytes" -Level "WARNING"
                Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch
        {
            Write-Log -Message "Download attempt $attempt failed: $( $_.Exception.Message )" -Level "WARNING"
            Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
        }

        if ($attempt -lt $MaxRetries)
        {
            Start-Sleep -Seconds (5 * $attempt)  # Increasing delay
        }
    }

    Write-Log -Message "All download attempts failed for: $Url" -Level "ERROR"
    return $false
}

function Extract-Package
{
    param([string]$PackagePath, [string]$DestinationPath, [string]$SevenZipPath)

    $extension = [System.IO.Path]::GetExtension($PackagePath).ToLower()

    try
    {
        if ($extension -eq ".7z" -and (Test-Path $SevenZipPath))
        {
            & $SevenZipPath x $PackagePath "-o$DestinationPath" -y | Out-Null
        }
        elseif ($extension -eq ".zip")
        {
            Expand-Archive -Path $PackagePath -DestinationPath $DestinationPath -Force
        }
        else
        {
            throw "Unsupported archive format: $extension"
        }
        return $true
    }
    catch
    {
        Write-Log -Message "Extraction failed: $( $_.Exception.Message )" -Level "ERROR"
        return $false
    }
}

function Normalize-ExtractedPath
{
    param([string]$ExtractPath)

    $items = Get-ChildItem -Path $ExtractPath
    if ($items.Count -eq 1 -and $items[0].PSIsContainer)
    {
        $nestedFolder = $items[0]
        Write-Log -Message "Normalizing nested folder: $( $nestedFolder.Name )" -Level "INFO"

        # Move all contents from nested folder to parent
        $subItems = Get-ChildItem -Path $nestedFolder.FullName -Force
        foreach ($item in $subItems)
        {
            Move-Item -Path $item.FullName -Destination $ExtractPath -Force
        }

        # Remove empty nested folder
        Remove-Item -Path $nestedFolder.FullName -Force
        Write-Log -Message "Normalized extraction path: $ExtractPath" -Level "INFO"
    }
}

function Verify-Executable
{
    param([string]$BasePath, [string]$ExecutablePath)

    $fullPath = Join-Path $BasePath $ExecutablePath
    if (Test-Path $fullPath)
    {
        try
        {
            if ($fullPath -like "*.exe")
            {
                $version = (Get-ItemProperty $fullPath).VersionInfo.FileVersion
                Write-Log -Message "Executable verified: $fullPath (Version: $version)" -Level "INFO"
            }
            else
            {
                Write-Log -Message "File verified: $fullPath" -Level "INFO"
            }
            return $true
        }
        catch
        {
            Write-Log -Message "Executable verification failed: $fullPath" -Level "WARNING"
            return $true  # Continue if version info unavailable
        }
    }
    return $false
}

function Invoke-Step5
{
    Write-Log -Message "Starting Step 5: Dependency Download/Validation" -Level "INFO"
    Update-Progress -Step 5 -Message "Processing dependencies..."

    try
    {
        $dependencies = $script:Config.dependencies
        $searchFolders = $dependencies.searchFolders
        $sevenZipPath = $null

        # Process 7zr first as it's needed for other extractions
        $sevenZrConfig = $dependencies.packages."7zr"
        Write-Log -Message "Processing dependency: $( $sevenZrConfig.name )" -Level "INFO"

        $targetPath = Join-Path $script:InstallPath $sevenZrConfig.targetSubfolder
        $sevenZipPath = Join-Path $targetPath "7zr.exe"

        # Check if already installed
        if (Test-Path $sevenZipPath)
        {
            Write-Log -Message "7zr.exe already installed at target location" -Level "INFO"
        }
        else
        {
            $localFile = Find-LocalPackage -FilePattern $sevenZrConfig.filePattern -SearchFolders $searchFolders -SupportedExtensions $sevenZrConfig.supportedExtensions

            # Check script root for previously downloaded file
            if (-not $localFile)
            {
                $scriptRootFile = Join-Path $PSScriptRoot "7zr.exe"
                if (Test-Path $scriptRootFile)
                {
                    $localFile = $scriptRootFile
                    Write-Log -Message "Found 7zr.exe in script directory" -Level "INFO"
                }
            }

            if (-not $localFile -and -not $sevenZrConfig.localOnly)
            {
                Write-Log -Message "7zr.exe not found locally, downloading..." -Level "INFO"
                $downloadPath = Join-Path $PSScriptRoot "7zr.exe"
                if (-not (Download-Package -Url $sevenZrConfig.downloadUrl -DestinationPath $downloadPath))
                {
                    throw "Failed to download 7zr.exe"
                }
                $localFile = $downloadPath
            }

            if ($localFile)
            {
                New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
                Copy-Item -Path $localFile -Destination $sevenZipPath -Force
                Write-Log -Message "7zr.exe installed successfully" -Level "INFO"
            }
        }

        # Process other dependencies
        foreach ($depKey in $dependencies.packages.PSObject.Properties.Name)
        {
            if ($depKey -eq "7zr")
            {
                continue
            }  # Already processed

            $depConfig = $dependencies.packages.$depKey
            Write-Log -Message "Processing dependency: $( $depConfig.name )" -Level "INFO"

            # Find local package
            $localFile = Find-LocalPackage -FilePattern $depConfig.filePattern -SearchFolders $searchFolders -SupportedExtensions $depConfig.supportedExtensions

            if ($localFile)
            {
                Write-Log -Message "Found local package: $localFile" -Level "INFO"
            }
            elseif (-not $depConfig.localOnly)
            {
                Write-Log -Message "Package not found locally, downloading from: $( $depConfig.downloadUrl )" -Level "INFO"
                $fileName = [System.IO.Path]::GetFileName($depConfig.downloadUrl)
                $downloadPath = Join-Path $PSScriptRoot $fileName

                # Retry download if integrity validation fails
                $downloadSuccess = $false
                for ($retry = 1; $retry -le 3; $retry++) {
                    if (Download-Package -Url $depConfig.downloadUrl -DestinationPath $downloadPath)
                    {
                        if (Test-FileIntegrity -FilePath $downloadPath -ExpectedSha256 $depConfig.sha256)
                        {
                            $downloadSuccess = $true
                            break
                        }
                        else
                        {
                            Write-Log -Message "Downloaded file failed integrity check, retry $retry/3" -Level "WARNING"
                        }
                    }
                }

                if (-not $downloadSuccess)
                {
                    throw "Failed to download or validate $( $depConfig.name ) after 3 attempts"
                }
                $localFile = $downloadPath
            }
            else
            {
                throw "$( $depConfig.name ) not found locally and local-only flag is set"
            }

            # Enhanced file integrity validation (skip if already validated during download)
            if ($localFile -notlike "$PSScriptRoot\*" -or -not $downloadSuccess)
            {
                if (-not (Test-FileIntegrity -FilePath $localFile -ExpectedSha256 $depConfig.sha256))
                {
                    throw "File integrity validation failed for $( $depConfig.name )"
                }
            }

            # Extract package
            $targetPath = Join-Path $script:InstallPath $depConfig.targetSubfolder

            # Remove existing target folder for clean re-install
            if (Test-Path $targetPath)
            {
                # Stop any processes using files in target path
                if ($depConfig.name -like "*procrun*" -or $depConfig.name -like "*daemon*")
                {
                    Get-Process | Where-Object { $_.Path -like "$targetPath\*" } | Stop-Process -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                }

                # Try to remove with retry logic
                $retryCount = 0
                $maxRetries = 3

                while ($retryCount -lt $maxRetries)
                {
                    try
                    {
                        Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop
                        break
                    }
                    catch
                    {
                        $retryCount++
                        if ($retryCount -eq $maxRetries)
                        {
                            Write-Log -Message "Failed to remove $targetPath after $maxRetries attempts, continuing with overlay install" -Level "WARNING"
                            break
                        }
                        Write-Log -Message "Retry $retryCount/$maxRetries removing $targetPath" -Level "INFO"
                        Start-Sleep -Seconds 3
                    }
                }
            }
            New-Item -Path $targetPath -ItemType Directory -Force | Out-Null

            if ($depConfig.supportedExtensions -contains ".exe")
            {
                # Direct executable copy
                Copy-Item -Path $localFile -Destination $targetPath -Force
            }
            else
            {
                # Extract archive
                Write-Log -Message "Extracting $( $depConfig.name ) to: $targetPath" -Level "INFO"
                if (-not (Extract-Package -PackagePath $localFile -DestinationPath $targetPath -SevenZipPath $sevenZipPath))
                {
                    throw "Failed to extract $( $depConfig.name )"
                }

                # Normalize path structure
                Normalize-ExtractedPath -ExtractPath $targetPath
            }

            # Verify executable
            if (-not (Verify-Executable -BasePath $targetPath -ExecutablePath $depConfig.verifyExecutable))
            {
                throw "Verification failed for $( $depConfig.name ) - executable not found: $( $depConfig.verifyExecutable )"
            }

            Write-Log -Message "$( $depConfig.name ) installed and verified successfully" -Level "INFO"
        }

        Write-Log -Message "All dependencies processed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "Dependency processing failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
# Database management functions
function Find-AvailablePort
{
    param([int]$StartPort, [int]$EndPort)

    for ($port = $StartPort; $port -le $EndPort; $port++) {
        try
        {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
            $listener.Start()
            $listener.Stop()
            Write-Log -Message "Port $port is available" -Level "INFO"
            return [int]$port
        }
        catch
        {
            Write-Log -Message "Port $port is occupied" -Level "INFO"
        }
    }
    return [int]0
}

function Create-SqlToolRc
{
    param([string]$FilePath, [string]$DatabaseName, [string]$Username, [string]$Password, [int]$Port, [string]$DataPath)

    $content = @"
# HSQLDB sqltool.rc configuration
urlid file_db
url jdbc:hsqldb:file:$DataPath\$DatabaseName
username $Username
password $Password

urlid mem_db
url jdbc:hsqldb:mem:$( $script:Config.database.memoryDbId )
username $Username
password $Password

urlid server_db
url jdbc:hsqldb:hsql://localhost:$Port/$DatabaseName
username $Username
password $Password
"@

    [System.IO.File]::WriteAllText($FilePath, $content, [System.Text.Encoding]::ASCII)
}

function Create-ServerProperties
{
    param([string]$FilePath, [string]$DatabaseName, [int]$Port, [string]$DataPath)

    # Convert Windows path to Unix format for HSQLDB
    $unixDataPath = $DataPath -replace '\\', '/'

    $content = @"
server.database.0=file:$unixDataPath/$DatabaseName
server.dbname.0=$DatabaseName
server.port=$Port
"@

    # Use ASCII encoding to avoid BOM issues
    [System.IO.File]::WriteAllText($FilePath, $content, [System.Text.Encoding]::ASCII)
}

function Execute-SqlScript
{
    param([string]$ScriptPath, [string]$RcFile, [string]$ConnectionName)

    try
    {
        $jreFolder = $script:Config.dependencies.packages.jre.targetSubfolder
        $hsqldbFolder = $script:Config.dependencies.packages.hsqldb.targetSubfolder

        $javaPath = Join-Path $script:InstallPath "$jreFolder\bin\java.exe"
        $sqltoolJar = Join-Path $script:InstallPath "$hsqldbFolder\hsqldb\lib\sqltool.jar"

        $output = & $javaPath -cp $sqltoolJar org.hsqldb.cmdline.SqlTool --autoCommit --rcFile=$RcFile $ConnectionName $ScriptPath 2>&1
        if ($LASTEXITCODE -ne 0)
        {
            Write-Log -Message "SQL execution failed with exit code: $LASTEXITCODE" -Level "ERROR"
            Write-Log -Message "SQL execution output: $output" -Level "ERROR"
            Write-Log -Message "Command: $javaPath -cp $sqltoolJar org.hsqldb.cmdline.SqlTool --autoCommit --rcFile=$RcFile $ConnectionName $ScriptPath" -Level "ERROR"
        }
        return $LASTEXITCODE -eq 0
    }
    catch
    {
        Write-Log -Message "SQL script execution failed: $( $_.Exception.Message )" -Level "ERROR"
        return $false
    }
}

function Execute-SqlQuery
{
    param([string]$Query, [string]$ConnectionName, [string]$RcFile)

    try
    {
        $jreFolder = $script:Config.dependencies.packages.jre.targetSubfolder
        $hsqldbFolder = $script:Config.dependencies.packages.hsqldb.targetSubfolder

        $javaPath = Join-Path $script:InstallPath "$jreFolder\bin\java.exe"
        $sqltoolJar = Join-Path $script:InstallPath "$hsqldbFolder\hsqldb\lib\sqltool.jar"

        $result = & $javaPath -cp $sqltoolJar org.hsqldb.cmdline.SqlTool --autoCommit --rcFile=$RcFile --sql="$Query" $ConnectionName
        return $result
    }
    catch
    {
        Write-Log -Message "SQL query execution failed: $( $_.Exception.Message )" -Level "ERROR"
        return $null
    }
}

function Start-HsqldbServer
{
    param([string]$PropertiesFile)

    try
    {
        $jreFolder = $script:Config.dependencies.packages.jre.targetSubfolder
        $hsqldbFolder = $script:Config.dependencies.packages.hsqldb.targetSubfolder

        $javaPath = Join-Path $script:InstallPath "$jreFolder\bin\java.exe"
        $hsqldbJar = Join-Path $script:InstallPath "$hsqldbFolder\hsqldb\lib\hsqldb.jar"

        # Set working directory to hsqldb folder
        $hsqldbFolder = $script:Config.dependencies.packages.hsqldb.targetSubfolder
        $workingDir = Join-Path $script:InstallPath $hsqldbFolder

        $process = Start-Process -FilePath $javaPath -ArgumentList "-cp", $hsqldbJar, "org.hsqldb.server.Server", "--props", $PropertiesFile -PassThru -WindowStyle Hidden -WorkingDirectory $workingDir
        Start-Sleep -Seconds 5  # Wait longer for server to start

        if (-not $process.HasExited)
        {
            Write-Log -Message "HSQLDB server started successfully (PID: $( $process.Id ))" -Level "INFO"
            return $process
        }
        else
        {
            Write-Log -Message "HSQLDB server process exited with code: $( $process.ExitCode )" -Level "ERROR"
            return $null
        }
    }
    catch
    {
        Write-Log -Message "Failed to start HSQLDB server: $( $_.Exception.Message )" -Level "ERROR"
        return $null
    }
}

function Stop-HsqldbServer
{
    param($Process, [string]$RcFile)

    if ($Process -and -not $Process.HasExited)
    {
        try
        {
            Execute-SqlQuery -Query "SHUTDOWN;" -ConnectionName "server_db" -RcFile $RcFile | Out-Null
            Start-Sleep -Seconds 3
        }
        catch
        {
        }
        if ($Process -and -not $Process.HasExited)
        {
            $Process.Kill()
        }
    }
}

function Invoke-Step6
{
    Write-Log -Message "Starting Step 6: Database Setup & Port Allocation" -Level "INFO"
    Update-Progress -Step 6 -Message "Setting up database..."

    try
    {
        $dbConfig = $script:Config.database

        # Find available port
        Write-Log -Message "Finding available port for HSQLDB" -Level "INFO"
        $availablePort = Find-AvailablePort -StartPort $dbConfig.portRange.start -EndPort $dbConfig.portRange.end

        if ($availablePort -eq 0)
        {
            throw "No available ports found in range $( $dbConfig.portRange.start )-$( $dbConfig.portRange.end )"
        }

        $script:DatabasePort = [int]($availablePort | Select-Object -First 1)

        Write-Log -Message "Selected port: $script:DatabasePort" -Level "INFO"

        # Create data directory
        $dataPath = Join-Path $script:InstallPath $dbConfig.dataDirectory
        New-Item -Path $dataPath -ItemType Directory -Force | Out-Null
        Write-Log -Message "Created data directory: $dataPath" -Level "INFO"

        # Copy initialization scripts for HSQLDB bootstrap
        foreach ($script in $dbConfig.initScripts)
        {
            $sourcePath = Join-Path $PSScriptRoot $script
            $destPath = Join-Path $dataPath ([System.IO.Path]::GetFileName($script))
            if (Test-Path $sourcePath)
            {
                Copy-Item -Path $sourcePath -Destination $destPath -Force
                Write-Log -Message "Copied bootstrap script: $([System.IO.Path]::GetFileName($script) )" -Level "INFO"
            }
        }

        # Copy application script
        $appScriptSource = Join-Path $PSScriptRoot $dbConfig.appScript
        $appScriptDest = Join-Path $dataPath $dbConfig.appScript
        if (Test-Path $appScriptSource)
        {
            Copy-Item -Path $appScriptSource -Destination $appScriptDest -Force
            Write-Log -Message "Copied application script: $( $dbConfig.appScript )" -Level "INFO"
        }

        # Create configuration files in hsqldb root
        $hsqldbFolder = $script:Config.dependencies.packages.hsqldb.targetSubfolder
        $jreFolder = $script:Config.dependencies.packages.jre.targetSubfolder
        $hsqldbPath = Join-Path $script:InstallPath $hsqldbFolder

        # Create sqltool.rc in hsqldb root
        $rcFile = Join-Path $hsqldbPath "sqltool.rc"
        Create-SqlToolRc -FilePath $rcFile -DatabaseName $dbConfig.name -Username $dbConfig.username -Password $dbConfig.password -Port $script:DatabasePort -DataPath $dataPath
        Write-Log -Message "Created sqltool.rc configuration" -Level "INFO"

        # Create server.properties in hsqldb root
        $propsFile = Join-Path $hsqldbPath "server.properties"
        Create-ServerProperties -FilePath $propsFile -DatabaseName $dbConfig.name -Port $script:DatabasePort -DataPath $dataPath
        Write-Log -Message "Created server.properties configuration" -Level "INFO"

        # Create database manager script in hsqldb root
        $dbManagerScript = Join-Path $hsqldbPath "DatabaseManager.bat"
        $dbManagerContent = @"
@echo off
setlocal

set JAVA_PATH=%~dp0..\$jreFolder\bin\java.exe
set HSQLDB_JAR=%~dp0hsqldb\lib\hsqldb.jar
set RC_FILE=%~dp0sqltool.rc

if not exist "%JAVA_PATH%" (
    echo Java not found at: %JAVA_PATH%
    pause
    exit /b 1
)

if not exist "%HSQLDB_JAR%" (
    echo HSQLDB JAR not found at: %HSQLDB_JAR%
    pause
    exit /b 1
)

if not exist "%RC_FILE%" (
    echo sqltool.rc not found at: %RC_FILE%
    pause
    exit /b 1
)

echo Starting HSQLDB Database Manager...
"%JAVA_PATH%" -cp "%HSQLDB_JAR%" org.hsqldb.util.DatabaseManagerSwing --rcFile "%RC_FILE%" --urlid server_db

pause
"@
        [System.IO.File]::WriteAllText($dbManagerScript, $dbManagerContent, [System.Text.Encoding]::ASCII)
        Write-Log -Message "Created database manager script: $dbManagerScript" -Level "INFO"

        # Start database server
        Write-Log -Message "Starting HSQLDB server" -Level "INFO"
        $dbProcess = Start-HsqldbServer -PropertiesFile $propsFile

        if (-not $dbProcess)
        {
            throw "Failed to start HSQLDB server"
        }

        # Execute application script
        $appScriptPath = Join-Path $dataPath $dbConfig.appScript
        Write-Log -Message "Executing application setup script: $appScriptPath" -Level "INFO"
        if (-not (Test-Path $appScriptPath))
        {
            Write-Log -Message "Application script not found: $appScriptPath" -Level "ERROR"
            throw "Application script not found: $appScriptPath"
        }
        if (-not (Execute-SqlScript -ScriptPath $appScriptPath -RcFile $rcFile -ConnectionName "server_db"))
        {
            throw "Failed to execute application setup script"
        }

        # Execute installation info query
        Write-Log -Message "Retrieving installation information" -Level "INFO"
        $installInfo = Execute-SqlQuery -Query $dbConfig.queries.installInfo -ConnectionName "server_db" -RcFile $rcFile
        if ( [string]::IsNullOrWhiteSpace($installInfo))
        {
            throw "Installation info query returned no results - database setup incomplete"
        }
        Write-Log -Message "Installation Info: $installInfo" -Level "INFO"

        # Execute FileCatalyst check query
        Write-Log -Message "Checking FileCatalyst HotFolder requirement" -Level "INFO"
        $hotfolderCheck = Execute-SqlQuery -Query $dbConfig.queries.fileCatalystCheck -ConnectionName "server_db" -RcFile $rcFile
        if ( [string]::IsNullOrWhiteSpace($hotfolderCheck))
        {
            throw "FileCatalyst check query returned no results - database setup incomplete"
        }
        $script:InstallFileCatalyst = ($hotfolderCheck -match "true")
        Write-Log -Message "FileCatalyst HotFolder required: $script:InstallFileCatalyst" -Level "INFO"

        # Stop database server for now
        Stop-HsqldbServer -Process $dbProcess -RcFile $rcFile
        Write-Log -Message "Database server stopped" -Level "INFO"

        Write-Log -Message "Database setup completed successfully" -Level "INFO"

    }
    catch
    {
        # Shutdown HSQLDB if it was started
        Write-Log -Message "Shutting down HSQLDB server due to error" -Level "INFO"
        Stop-HsqldbServer -Process $dbProcess -RcFile $rcFile
        Write-Log -Message "Database setup failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
# FileCatalyst management functions
function Get-FileCatalystInstallDir
{
    param([string]$SettingsFile)

    if (Test-Path $SettingsFile)
    {
        $content = Get-Content $SettingsFile
        foreach ($line in $content)
        {
            if ($line -match "Dir=(.+)")
            {
                return $matches[1]
            }
        }
    }
    return $null
}

function Create-HotFoldersXml
{
    param([string]$FilePath, [string]$HotFolderId, [string]$HotFolderLocation)

    $xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<HotFolderList>
    <HotFolder ID="$HotFolderId" Location="$HotFolderLocation"/>
</HotFolderList>
"@

    [System.IO.File]::WriteAllText($FilePath, $xmlContent, [System.Text.Encoding]::ASCII)
}

function Update-HotFoldersXml
{
    param([string]$FilePath, [string]$HotFolderId, [string]$HotFolderLocation)

    if (Test-Path $FilePath)
    {
        $content = Get-Content $FilePath -Raw
        if ($content -notmatch "ID=`"$HotFolderId`"")
        {
            # Add new hotfolder entry
            $newEntry = "    <HotFolder ID=`"$HotFolderId`" Location=`"$HotFolderLocation`"/>"
            $content = $content -replace "</HotFolderList>", "$newEntry`n</HotFolderList>"
            [System.IO.File]::WriteAllText($FilePath, $content, [System.Text.Encoding]::ASCII)
            return $true
        }
        return $false  # Already exists
    }
    else
    {
        Create-HotFoldersXml -FilePath $FilePath -HotFolderId $HotFolderId -HotFolderLocation $HotFolderLocation
        return $true
    }
}

function Install-FileCatalyst
{
    param([string]$InstallerPath, [string]$SettingsFile, [bool]$UseExistingSettings)

    try
    {
        $fcConfig = $script:Config.filecatalyst

        if ($UseExistingSettings -and (Test-Path $SettingsFile))
        {
            # Load existing settings and install silently
            $args = @($fcConfig.loadInfCommand.Split(' ') + "=`"$SettingsFile`"" + $fcConfig.noRestartArg)
            Write-Log -Message "Installing FileCatalyst with existing settings" -Level "INFO"
        }
        else
        {
            # Generate settings file only (no installation)
            Write-Log -Message "Generating FileCatalyst settings file" -Level "INFO"
            $saveArgs = @($fcConfig.saveInfCommand + "=`"$SettingsFile`"")
            $saveProcess = Start-Process -FilePath $InstallerPath -ArgumentList $saveArgs -Wait -PassThru

            if ($saveProcess.ExitCode -ne 0)
            {
                throw "Failed to generate settings file"
            }

            Write-Log -Message "FileCatalyst settings file generated successfully" -Level "INFO"
            return $true  # Skip actual installation, just generate settings
        }

        Write-Log -Message "Running FileCatalyst installer: $InstallerPath $( $args -join ' ' )" -Level "INFO"
        $process = Start-Process -FilePath $InstallerPath -ArgumentList $args -Wait -PassThru

        return $process.ExitCode -eq 0
    }
    catch
    {
        Write-Log -Message "FileCatalyst installation failed: $( $_.Exception.Message )" -Level "ERROR"
        return $false
    }
}

function Invoke-Step7
{
    Write-Log -Message "Starting Step 7: FileCatalyst Installation" -Level "INFO"
    Update-Progress -Step 7 -Message "Processing FileCatalyst..."

    try
    {
        # Check if FileCatalyst should be installed based on flag set in Step 6
        if (-not $script:InstallFileCatalyst)
        {
            Write-Log -Message "FileCatalyst installation not required based on database settings" -Level "INFO"
            return
        }

        Write-Log -Message "FileCatalyst installation required" -Level "INFO"

        $fcConfig = $script:Config.filecatalyst
        $searchFolders = $script:Config.dependencies.searchFolders

        # Find FileCatalyst installer
        Write-Log -Message "Searching for FileCatalyst installer" -Level "INFO"
        $installerPath = Find-LocalPackage -FilePattern $fcConfig.installerPattern -SearchFolders $searchFolders -SupportedExtensions $fcConfig.supportedExtensions

        # Check script root for previously downloaded file
        if (-not $installerPath)
        {
            $fileName = [System.IO.Path]::GetFileName($fcConfig.downloadUrl)
            $scriptRootFile = Join-Path $PSScriptRoot $fileName
            if (Test-Path $scriptRootFile)
            {
                $installerPath = $scriptRootFile
                Write-Log -Message "Found FileCatalyst installer in script directory" -Level "INFO"
            }
        }

        if (-not $installerPath)
        {
            Write-Log -Message "FileCatalyst installer not found locally, downloading..." -Level "INFO"
            $fileName = [System.IO.Path]::GetFileName($fcConfig.downloadUrl)
            $downloadPath = Join-Path $PSScriptRoot $fileName

            if (-not (Download-Package -Url $fcConfig.downloadUrl -DestinationPath $downloadPath))
            {
                throw "Failed to download FileCatalyst installer"
            }
            $installerPath = $downloadPath
        }

        Write-Log -Message "Found FileCatalyst installer: $installerPath" -Level "INFO"

        # Extract if zipped
        if ([System.IO.Path]::GetExtension($installerPath) -eq ".zip")
        {
            Write-Log -Message "Extracting FileCatalyst installer from ZIP" -Level "INFO"
            $extractPath = Join-Path $PSScriptRoot "fc_temp"
            New-Item -Path $extractPath -ItemType Directory -Force | Out-Null

            Expand-Archive -Path $installerPath -DestinationPath $extractPath -Force
            $extractedExe = Get-ChildItem -Path $extractPath -Filter "*.exe" | Select-Object -First 1

            if (-not $extractedExe)
            {
                throw "No executable found in FileCatalyst ZIP archive"
            }

            $installerPath = $extractedExe.FullName
            Write-Log -Message "Extracted installer: $installerPath" -Level "INFO"
        }

        # Check for existing settings file
        $settingsFile = Join-Path $PSScriptRoot $fcConfig.settingsFile
        $useExistingSettings = $false

        if (Test-Path $settingsFile)
        {
            Write-Log -Message "Found existing FileCatalyst settings file" -Level "INFO"
            $promptMsg = @"
FileCatalyst HotFolder Setup

We found previous installation settings on your computer.

Do you want to:
• YES - Use your previous settings (faster, keeps your preferences)
• NO - Create new settings (fresh start, will ask for preferences again)

Recommended: Choose YES unless you want to change your previous setup.
"@
            $result = Show-Message -Message $promptMsg -Title "FileCatalyst Installation Options" -Buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -Icon ([System.Windows.Forms.MessageBoxIcon]::Question)
            $useExistingSettings = ($result -eq [System.Windows.Forms.DialogResult]::Yes)

            if ($useExistingSettings)
            {
                Write-Log -Message "User chose to use existing settings" -Level "INFO"
            }
            else
            {
                Write-Log -Message "User chose fresh installation" -Level "INFO"
            }
        }
        else
        {
            Write-Log -Message "No existing settings file found, performing fresh installation" -Level "INFO"
        }

        # Install FileCatalyst
        if (-not (Install-FileCatalyst -InstallerPath $installerPath -SettingsFile $settingsFile -UseExistingSettings $useExistingSettings))
        {
            throw "FileCatalyst installation failed"
        }

        Write-Log -Message "FileCatalyst installation completed successfully" -Level "INFO"

        # Get installation directory from settings file
        $fcInstallDir = Get-FileCatalystInstallDir -SettingsFile $settingsFile
        if ($fcInstallDir)
        {
            Write-Log -Message "FileCatalyst installed to: $fcInstallDir" -Level "INFO"

            # Create/update hotfolders.xml
            $hotfoldersXml = Join-Path $fcInstallDir "hotfolders.xml"
            $hotFolderLocation = $fcConfig.hotFolderLocation -replace "\{install_path\}", $script:InstallPath

            # Create HotFolder directory if it doesn't exist
            if (-not (Test-Path $hotFolderLocation))
            {
                New-Item -Path $hotFolderLocation -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created HotFolder directory: $hotFolderLocation" -Level "INFO"
            }

            # Convert to Unix path format for FileCatalyst
            $hotFolderLocation = $hotFolderLocation -replace '\\', '/'
            $updated = Update-HotFoldersXml -FilePath $hotfoldersXml -HotFolderId $fcConfig.hotFolderId -HotFolderLocation $hotFolderLocation

            if ($updated)
            {
                Write-Log -Message "Updated hotfolders.xml with iCamera hotfolder configuration" -Level "INFO"
            }
            else
            {
                Write-Log -Message "iCamera hotfolder already exists in hotfolders.xml" -Level "INFO"
            }
        }
        else
        {
            Write-Log -Message "Could not determine FileCatalyst installation directory" -Level "WARNING"
        }

        # Cleanup temporary files
        $tempPath = Join-Path $PSScriptRoot "fc_temp"
        if (Test-Path $tempPath)
        {
            Remove-Item -Path $tempPath -Recurse -Force
        }

        Write-Log -Message "FileCatalyst setup completed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "FileCatalyst setup failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
# Application setup functions
function Update-PropertiesFile
{
    param([string]$FilePath, [hashtable]$Updates)

    if (Test-Path $FilePath)
    {
        $content = Get-Content $FilePath

        foreach ($key in $Updates.Keys)
        {
            $value = $Updates[$key]
            $updated = $false

            for ($i = 0; $i -lt $content.Length; $i++) {
                if ($content[$i] -match "^$key\s*=")
                {
                    $content[$i] = "$key=$value"
                    $updated = $true
                    Write-Log -Message "Updated property: $key=$value" -Level "INFO"
                    break
                }
            }

            if (-not $updated)
            {
                $content += "$key=$value"
                Write-Log -Message "Added property: $key=$value" -Level "INFO"
            }
        }

        [System.IO.File]::WriteAllText($FilePath, ($content -join "`n"), [System.Text.Encoding]::ASCII)
    }
}

function Update-LogbackXml
{
    param([string]$FilePath, [string]$LogLevel)

    if (Test-Path $FilePath)
    {
        $content = Get-Content $FilePath -Raw
        $content = $content -replace '<root level="[^"]*">', "<root level=`"$LogLevel`">"
        [System.IO.File]::WriteAllText($FilePath, $content, [System.Text.Encoding]::ASCII)
        Write-Log -Message "Updated logback.xml log level to: $LogLevel" -Level "INFO"
    }
}

function Get-FileCatalystPaths
{
    $fcConfig = $script:Config.filecatalyst
    $settingsFile = Join-Path $PSScriptRoot $fcConfig.settingsFile

    $installPath = Get-FileCatalystInstallDir -SettingsFile $settingsFile
    if (-not $installPath)
    {
        $installPath = "C:/Program Files/FileCatalyst/HotFolder"  # Default fallback
    }

    $hotFolderPath = $fcConfig.hotFolderLocation -replace "\{install_path\}", $script:InstallPath

    return @{
        InstallPath = $installPath
        HotFolderPath = $hotFolderPath
    }
}

function Invoke-Step8
{
    Write-Log -Message "Starting Step 8: Setup Application" -Level "INFO"
    Update-Progress -Step 8 -Message "Setting up application files..."

    try
    {
        $appConfig = $script:Config.application
        $dbConfig = $script:Config.database

        # Create application destination folder
        $appPath = Join-Path $script:InstallPath $appConfig.destinationFolder
        New-Item -Path $appPath -ItemType Directory -Force | Out-Null
        Write-Log -Message "Created application directory: $appPath" -Level "INFO"

        # Copy application files
        foreach ($file in $appConfig.files)
        {
            $sourcePath = Join-Path $PSScriptRoot $file
            $destPath = Join-Path $appPath $file

            if (Test-Path $sourcePath)
            {
                Copy-Item -Path $sourcePath -Destination $destPath -Force
                Write-Log -Message "Copied file: $file" -Level "INFO"
            }
            else
            {
                Write-Log -Message "Source file not found: $file" -Level "WARNING"
            }
        }

        # Get FileCatalyst paths
        $fcPaths = Get-FileCatalystPaths
        $ffmpegFolder = $script:Config.dependencies.packages.ffmpeg.targetSubfolder
        Write-Log -Message "FileCatalyst install path: $( $fcPaths.InstallPath )" -Level "INFO"
        Write-Log -Message "FileCatalyst hotfolder path: $( $fcPaths.HotFolderPath )" -Level "INFO"

        # Update proxy-details.properties
        $propertiesFile = Join-Path $appPath "proxy-details.properties"
        if (Test-Path $propertiesFile)
        {
            Write-Log -Message "Updating proxy-details.properties" -Level "INFO"

            # Prepare database URL
            $dbUrl = $appConfig.configurations."proxy-details.properties".url
            $dbUrl = $dbUrl -replace "\{port\}", $script:DatabasePort
            $dbUrl = $dbUrl -replace "\{dbname\}", $dbConfig.name

            # Prepare FileCatalyst paths
            $fcInstallPath = $appConfig.configurations."proxy-details.properties"."filecatalyst.install.path"
            $fcInstallPath = $fcInstallPath -replace "\{fc_install_path\}", $fcPaths.InstallPath

            $fcHotfolderPath = $appConfig.configurations."proxy-details.properties"."filecatalyst.hotfolder.path"
            $fcHotfolderPath = $fcHotfolderPath -replace "\{fc_hotfolder_path\}", $fcPaths.HotFolderPath

            # Update properties
            $ffmpegPath = Join-Path $script:InstallPath "$ffmpegFolder\bin"
            $updates = @{
                "url" = $dbUrl
                "filecatalyst.install.path" = $fcPaths.InstallPath
                "filecatalyst.hotfolder.path" = $fcPaths.HotFolderPath
                "ffmpeg.path" = $ffmpegPath
            }

            Update-PropertiesFile -FilePath $propertiesFile -Updates $updates
        }

        # Update logback.xml
        $logbackFile = Join-Path $appPath "logback.xml"
        if (Test-Path $logbackFile)
        {
            Write-Log -Message "Updating logback.xml" -Level "INFO"
            $logLevel = $appConfig.configurations."logback.xml".logLevel
            Update-LogbackXml -FilePath $logbackFile -LogLevel $logLevel
        }

        # Create logs directory
        $logsPath = Join-Path $appPath $appConfig.logsFolder
        New-Item -Path $logsPath -ItemType Directory -Force | Out-Null
        Write-Log -Message "Created logs directory: $logsPath" -Level "INFO"

        # Set ACL permissions for logs directory
        Set-DirectoryPermissions -Path $logsPath

        Write-Log -Message "Application setup completed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "Application setup failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
# Service registration functions
function Register-WindowsService
{
    param([string]$ServiceName, $ServiceConfig, [string]$InstallPath)

    try
    {
        $procrunFolder = $script:Config.dependencies.packages.procrun.targetSubfolder
        $jreFolder = $script:Config.dependencies.packages.jre.targetSubfolder
        $hsqldbFolder = $script:Config.dependencies.packages.hsqldb.targetSubfolder

        $procrunPath = Join-Path $InstallPath "$procrunFolder\prunsrv.exe"
        $javaPath = Join-Path $InstallPath "$jreFolder\bin\java.exe"
        $hsqldbJar = Join-Path $InstallPath "$hsqldbFolder\hsqldb\lib\hsqldb.jar"

        # Expand path placeholders from service configuration
        $workingDir = $ServiceConfig.workingDirectory -replace "\{install_path\}", $InstallPath
        $workingDir = $workingDir -replace "\{hsqldb_folder\}", $script:Config.dependencies.packages.hsqldb.targetSubfolder
        $workingDir = $workingDir -replace "\{proxy_folder\}", $script:Config.application.destinationFolder
        $workingDir = $workingDir -replace "\{logs_folder\}", $script:Config.application.logsFolder
        $stdOutput = $ServiceConfig.stdOutput -replace "\{install_path\}", $InstallPath
        $stdOutput = $stdOutput -replace "\{logs_folder\}", $script:Config.application.logsFolder
        $stdOutput = Join-Path $InstallPath $stdOutput
        
        $stdError = $ServiceConfig.stdError -replace "\{install_path\}", $InstallPath
        $stdError = $stdError -replace "\{logs_folder\}", $script:Config.application.logsFolder
        $stdError = Join-Path $InstallPath $stdError

        # Create log directories
        $logDir = Split-Path $stdOutput -Parent
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null

        # Check if service exists
        $serviceExists = Get-Service -Name $ServiceConfig.name -ErrorAction SilentlyContinue
        $useInstall = -not $serviceExists

        if ($useInstall)
        {
            # Install new service
            $installArgs = @(
                "//IS//$( $ServiceConfig.name )"
                "--DisplayName=$( $ServiceConfig.displayName )"
                "--Description=$( $ServiceConfig.description )"
            )

            Write-Log -Message "Installing new service: $( $ServiceConfig.name )" -Level "INFO"
            Write-Log -Message "Install command: $procrunPath $( $installArgs -join ' ' )" -Level "INFO"
            & $procrunPath $installArgs

            if ($LASTEXITCODE -ne 0)
            {
                throw "Service installation failed with exit code: $LASTEXITCODE"
            }
        }
        else
        {
            Write-Log -Message "Service exists, updating configuration: $( $ServiceConfig.name )" -Level "INFO"
        }

        # Update service configuration
        $jreHome = Join-Path $InstallPath $jreFolder
        $updateArgs = @(
            "//US//$( $ServiceConfig.name )"
            "--JavaHome=$jreHome"
            "--StartMode=Java"
            "--StopMode=Java"
            "--StartClass=$( $ServiceConfig.mainClass )"
            "--Classpath=$hsqldbJar"
            "--LogPath=$logDir"
            "--StartPath=$InstallPath"
            "--StdOutput=$stdOutput"
            "--StdError=$stdError"
            "--ServiceUser=LocalSystem"
        )

        # Add JVM options with path expansion
        if ($ServiceConfig.jvmOptions)
        {
            $expandedJvmOpts = @()
            foreach ($opt in $ServiceConfig.jvmOptions)
            {
                $expandedOpt = $opt -replace "\{install_path\}", $InstallPath
                $expandedOpt = $expandedOpt -replace "\{hsqldb_folder\}", $script:Config.dependencies.packages.hsqldb.targetSubfolder
                $expandedOpt = $expandedOpt -replace "\{ffmpeg_folder\}", $script:Config.dependencies.packages.ffmpeg.targetSubfolder
                $expandedOpt = $expandedOpt -replace "\{proxy_folder\}", $script:Config.application.destinationFolder
                $expandedOpt = $expandedOpt -replace "\{logs_folder\}", $script:Config.application.logsFolder
                $expandedJvmOpts += $expandedOpt
            }
            $jvmOpts = $expandedJvmOpts -join ';'
            $updateArgs += "--JvmOptions=$jvmOpts"
        }

        # Add startup arguments with path expansion
        if ($ServiceConfig.arguments)
        {
            $expandedArgs = @()
            foreach ($arg in $ServiceConfig.arguments)
            {
                $expandedArg = $arg -replace "\{install_path\}", $InstallPath
                $expandedArg = $expandedArg -replace "\{hsqldb_folder\}", $script:Config.dependencies.packages.hsqldb.targetSubfolder
                $expandedArg = $expandedArg -replace "\{proxy_folder\}", $script:Config.application.destinationFolder
                $expandedArg = $expandedArg -replace "\{logs_folder\}", $script:Config.application.logsFolder
                $expandedArgs += $expandedArg
            }
            $startArgs = $expandedArgs -join ';'
            $updateArgs += "--StartParams=$startArgs"
        }

        # Add dependency
        if ($ServiceConfig.dependsOn)
        {
            $updateArgs += "--DependsOn=$( $ServiceConfig.dependsOn )"
        }

        # Add environment variables for iCamera Proxy
        if ($ServiceConfig.environmentVars)
        {
            $envVars = @()
            foreach ($key in $ServiceConfig.environmentVars.Keys)
            {
                $value = $ServiceConfig.environmentVars[$key] -replace "\{install_path\}", $InstallPath
                $value = $value -replace "\{proxy_folder\}", $script:Config.application.destinationFolder
                $value = $value -replace "\{logs_folder\}", $script:Config.application.logsFolder
                $value = $value -replace "\{ffmpeg_folder\}", $script:Config.dependencies.packages.ffmpeg.targetSubfolder
                $envVars += "$key=$value"
            }
            if ($envVars.Count -gt 0)
            {
                $updateArgs += "--Environment=$( $envVars -join ';' )"
            }
        }

        # Special handling for iCamera Proxy JAR
        if ($ServiceConfig.jarFile)
        {
            $jarPath = Join-Path $workingDir $ServiceConfig.jarFile
            $updateArgs = $updateArgs | Where-Object { $_ -notlike "--Classpath=*" }
            $updateArgs += "--Classpath=$jarPath"
        }

        Write-Log -Message "Updating service configuration: $( $ServiceConfig.name )" -Level "INFO"
        Write-Log -Message "Update command: $procrunPath $( $updateArgs -join ' ' )" -Level "INFO"
        & $procrunPath $updateArgs

        if ($LASTEXITCODE -ne 0)
        {
            throw "Service configuration update failed with exit code: $LASTEXITCODE"
        }

        # Configure failure recovery
        $scArgs = @(
            "failure", $ServiceConfig.name, "reset=", $ServiceConfig.resetInterval, "actions=", "restart/$( $ServiceConfig.restartDelay )/restart/$( $ServiceConfig.restartDelay * 2 )/restart/$( $ServiceConfig.restartDelay * 3 )"
        )

        & sc.exe $scArgs | Out-Null

        Write-Log -Message "Service $( $ServiceConfig.name ) registered successfully" -Level "INFO"
        return $true

    }
    catch
    {
        Write-Log -Message "Failed to register service $( $ServiceConfig.name ): $( $_.Exception.Message )" -Level "ERROR"
        return $false
    }
}

function Invoke-Step9
{
    Write-Log -Message "Starting Step 9: Service Registration" -Level "INFO"
    Update-Progress -Step 9 -Message "Registering services..."

    try
    {
        $servicesConfig = $script:Config.services

        # Register HSQLDB service first
        Write-Log -Message "Registering HSQLDB service" -Level "INFO"
        if (-not (Register-WindowsService -ServiceName "hsqldb" -ServiceConfig $servicesConfig.hsqldb -InstallPath $script:InstallPath))
        {
            throw "Failed to register HSQLDB service"
        }

        # Register iCamera Proxy service (depends on HSQLDB)
        Write-Log -Message "Registering iCamera Proxy service" -Level "INFO"
        if (-not (Register-WindowsService -ServiceName "icameraproxy" -ServiceConfig $servicesConfig.icameraproxy -InstallPath $script:InstallPath))
        {
            throw "Failed to register iCamera Proxy service"
        }

        Write-Log -Message "Service registration completed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "Service registration failed: $( $_.Exception.Message )" -Level "ERROR"
        throw
    }
}
function Test-ServiceRunning
{
    param([string]$ServiceName)

    try
    {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        return ($service -and $service.Status -eq 'Running')
    }
    catch
    {
        return $false
    }
}

function Wait-ForService
{
    param([string]$ServiceName, [int]$TimeoutSeconds = 30)

    $timeout = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempts = 0
    $maxAttempts = [math]::Floor($TimeoutSeconds / 2)

    while ((Get-Date) -lt $timeout -and $attempts -lt $maxAttempts)
    {
        $attempts++

        if (Test-ServiceRunning -ServiceName $ServiceName)
        {
            Write-Log -Message "Service $ServiceName started successfully after $( $attempts * 2 ) seconds" -Level "INFO"
            return $true
        }

        # Check service status for better error reporting
        try
        {
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($service)
            {
                Write-Log -Message "Service $ServiceName status: $( $service.Status ) (attempt $attempts/$maxAttempts)" -Level "INFO"

                # If service is stopped or failed, don't continue waiting
                if ($service.Status -eq 'Stopped')
                {
                    Write-Log -Message "Service $ServiceName is stopped, will not start automatically" -Level "ERROR"
                    return $false
                }
            }
        }
        catch
        {
            Write-Log -Message "Could not check service status for $ServiceName" -Level "WARNING"
        }

        Start-Sleep -Seconds 2
    }

    Write-Log -Message "Service $ServiceName failed to start after $TimeoutSeconds seconds ($attempts attempts)" -Level "ERROR"
    return $false
}

function Invoke-Step10
{
    Write-Log -Message "Starting Step 10: Service Startup & Validation" -Level "INFO"
    Update-Progress -Step 10 -Message "Starting and validating services..."

    try
    {
        $servicesConfig = $script:Config.services
        $hsqldbService = $servicesConfig.hsqldb.name
        $proxyService = $servicesConfig.icameraproxy.name

        # Start HSQLDB service
        Write-Log -Message "Starting HSQLDB service: $hsqldbService" -Level "INFO"
        try
        {
            Start-Service -Name $hsqldbService -ErrorAction Stop
        }
        catch
        {
            Write-Log -Message "Failed to start HSQLDB service: $( $_.Exception.Message )" -Level "ERROR"
            throw "HSQLDB service startup failed: $( $_.Exception.Message )"
        }

        # Wait for HSQLDB to be running
        Write-Log -Message "Waiting for HSQLDB service to start..." -Level "INFO"
        if (-not (Wait-ForService -ServiceName $hsqldbService -TimeoutSeconds 30))
        {
            Write-Log -Message "HSQLDB service failed to start within 30 seconds" -Level "ERROR"
            throw "HSQLDB service failed to start within timeout period"
        }
        Write-Log -Message "HSQLDB service is running successfully" -Level "INFO"

        # Start iCamera Proxy service
        Write-Log -Message "Starting iCamera Proxy service: $proxyService" -Level "INFO"
        try
        {
            Start-Service -Name $proxyService -ErrorAction Stop
        }
        catch
        {
            Write-Log -Message "Failed to start iCamera Proxy service: $( $_.Exception.Message )" -Level "ERROR"
            throw "iCamera Proxy service startup failed: $( $_.Exception.Message )"
        }

        # Wait for iCamera Proxy to be running
        Write-Log -Message "Waiting for iCamera Proxy service to start..." -Level "INFO"
        if (-not (Wait-ForService -ServiceName $proxyService -TimeoutSeconds 45))
        {
            Write-Log -Message "iCamera Proxy service failed to start within 45 seconds" -Level "ERROR"
            throw "iCamera Proxy service failed to start within timeout period"
        }
        Write-Log -Message "iCamera Proxy service is running successfully" -Level "INFO"

        # Final validation - both services must be running
        $hsqldbRunning = Test-ServiceRunning -ServiceName $hsqldbService
        $proxyRunning = Test-ServiceRunning -ServiceName $proxyService

        if ($hsqldbRunning -and $proxyRunning)
        {
            Write-Log -Message "All services validated successfully" -Level "INFO"

            # Log installation completion
            $endTime = Get-Date
            Write-Log -Message "Installation completed successfully at: $endTime" -Level "INFO"
            Write-Log -Message "Installation log file: $script:LogFile" -Level "INFO"

            # Show success message to user
            $successMsg = @"
iCamera Proxy installation completed successfully!

Services Status:
✓ HSQLDB Service ($hsqldbService): Running
✓ iCamera Proxy Service ($proxyService): Running

Installation Details:
• Installation Path: $script:InstallPath
• Database Port: $script:DatabasePort
• Log File: $script:LogFile

Both services are configured to start automatically on system boot.
"@

            Show-Message -Message $successMsg -Title "Installation Complete" -Icon ([System.Windows.Forms.MessageBoxIcon]::Information)

        }
        else
        {
            $errorMsg = "Service validation failed - "
            if (-not $hsqldbRunning)
            {
                $errorMsg += "HSQLDB service not running. "
            }
            if (-not $proxyRunning)
            {
                $errorMsg += "iCamera Proxy service not running."
            }
            throw $errorMsg
        }

        Write-Log -Message "Service startup and validation completed successfully" -Level "INFO"

    }
    catch
    {
        Write-Log -Message "Service startup and validation failed: $( $_.Exception.Message )" -Level "ERROR"

        # Show failure message to user
        $failureMsg = @"
iCamera Proxy installation failed!

Error: $( $_.Exception.Message )

Please check the installation log for details:
$script:LogFile

You may need to:
1. Check system requirements
2. Verify all dependencies are installed
3. Run the installer as administrator
4. Review the log file for specific errors
"@

        Show-Error -Message $failureMsg -Title "Installation Failed"
        throw
    }
}

# Main installation process
function Start-Installation
{
    param([System.Windows.Forms.Button]$StartButton)

    Write-Log -Message "Starting installation process" -Level "INFO"

    # Disable/hide start button
    $StartButton.Enabled = $false
    $StartButton.Visible = $false

    try
    {
        for ($i = 1; $i -le $script:Config.installation.totalSteps; $i++) {
            & "Invoke-Step$i"
            Start-Sleep -Milliseconds 500  # Simulate work
        }

        Write-Log -Message "Installation completed successfully" -Level "INFO"
        Show-Message -Message "Installation completed successfully!" -Title "Success"

        # Change button to Close after successful installation
        $StartButton.Text = "Close"
        $StartButton.BackColor = [System.Drawing.Color]::Gray
        $StartButton.Add_Click({ $script:MainForm.Close() })
    }
    catch
    {
        Write-Log -Message "Installation failed: $( $_.Exception.Message )" -Level "ERROR"
        Show-Error -Message $_.Exception.Message

        # Change button to Close after failed installation
        $StartButton.Text = "Close"
        $StartButton.BackColor = [System.Drawing.Color]::Gray
        $StartButton.Add_Click({ $script:MainForm.Close() })
    }
}

# Uninstall functions
function Remove-Services
{
    try
    {
        $servicesConfig = $script:Config.services

        # Stop and remove iCamera Proxy service
        $proxyService = $servicesConfig.icameraproxy.name
        if (Get-Service -Name $proxyService -ErrorAction SilentlyContinue)
        {
            Write-Log -Message "Stopping and removing service: $proxyService" -Level "INFO"
            Stop-Service -Name $proxyService -Force -ErrorAction SilentlyContinue
            & sc.exe delete $proxyService
        }

        # Stop and remove HSQLDB service
        $hsqldbService = $servicesConfig.hsqldb.name
        if (Get-Service -Name $hsqldbService -ErrorAction SilentlyContinue)
        {
            Write-Log -Message "Stopping and removing service: $hsqldbService" -Level "INFO"
            Stop-Service -Name $hsqldbService -Force -ErrorAction SilentlyContinue
            & sc.exe delete $hsqldbService
        }

        Write-Log -Message "Services removed successfully" -Level "INFO"
    }
    catch
    {
        Write-Log -Message "Error removing services: $( $_.Exception.Message )" -Level "ERROR"
    }
}

function Remove-InstallationFiles
{
    try
    {
        # Find installation directories
        $possiblePaths = @("C:\iCamera", "D:\iCamera", "E:\iCamera", "F:\iCamera")

        foreach ($path in $possiblePaths)
        {
            if (Test-Path $path)
            {
                Write-Log -Message "Removing installation directory: $path" -Level "INFO"
                Remove-Item -Path $path -Recurse -Force -ErrorAction Continue
                Write-Log -Message "Installation directory removed: $path" -Level "INFO"
            }
        }
    }
    catch
    {
        Write-Log -Message "Error removing installation files: $( $_.Exception.Message )" -Level "ERROR"
    }
}

function Remove-ScheduledTasks
{
    try
    {
        $taskName = $script:Config.cleanup.taskName
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

        if ($task)
        {
            Write-Log -Message "Removing scheduled task: $taskName" -Level "INFO"
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Log -Message "Scheduled task removed: $taskName" -Level "INFO"
        }
    }
    catch
    {
        Write-Log -Message "Error removing scheduled tasks: $( $_.Exception.Message )" -Level "ERROR"
    }
}

function Start-Uninstall
{
    Write-Log -Message "Starting iCamera Proxy uninstallation" -Level "INFO"

    try
    {
        Write-Host "Uninstalling iCamera Proxy..." -ForegroundColor Yellow

        # Remove services
        Write-Host "Removing services..." -ForegroundColor Green
        Remove-Services

        # Remove scheduled tasks
        Write-Host "Removing scheduled tasks..." -ForegroundColor Green
        Remove-ScheduledTasks

        # Remove installation files
        Write-Host "Removing installation files..." -ForegroundColor Green
        Remove-InstallationFiles

        Write-Log -Message "Uninstallation completed successfully" -Level "INFO"
        Write-Host "iCamera Proxy has been successfully uninstalled." -ForegroundColor Green

    }
    catch
    {
        $errorMsg = "Uninstallation failed: $( $_.Exception.Message )"
        Write-Log -Message $errorMsg -Level "ERROR"
        Write-Host $errorMsg -ForegroundColor Red
        exit 1
    }
}

# Hide console window
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0) | Out-Null

# Main entry point
function Main
{
    try
    {
        # Initialize logging first
        Initialize-Logging

        # Check for uninstall argument
        if ($Uninstall)
        {
            # Check admin rights and elevate if needed
            if (-not (Test-AdminRights))
            {
                Write-Log -Message "Requesting admin elevation for uninstall" -Level "INFO"
                Request-AdminElevation
            }

            # Load configuration
            $script:Config = Get-Configuration

            # Run uninstall
            Start-Uninstall
            return
        }

        # Check for existing instance
        if (-not (Test-ExistingInstance))
        {
            exit 1
        }

        # Load configuration
        $script:Config = Get-Configuration

        # Check admin rights and elevate if needed
        if (-not (Test-AdminRights))
        {
            Write-Log -Message "Requesting admin elevation" -Level "INFO"
            Release-Mutex
            Request-AdminElevation
        }

        Write-Log -Message "Admin rights confirmed" -Level "INFO"

        # Initialize GUI
        $script:MainForm = Initialize-MainWindow
        $script:ProgressBar = Add-ProgressBar -Form $script:MainForm
        $script:StatusLabel = Add-StatusLabel -Form $script:MainForm

        # Add log display
        $script:LogDisplay = Add-LogDisplay -Form $script:MainForm

        # Add start button
        $startButton = New-Object System.Windows.Forms.Button
        $startButton.Location = New-Object System.Drawing.Point(350, 520)
        $startButton.Size = New-Object System.Drawing.Size(120, 35)
        $startButton.Anchor = "Bottom"
        $startButton.Text = "Start Installation"
        $startButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $startButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
        $startButton.ForeColor = [System.Drawing.Color]::White
        $startButton.FlatStyle = "Flat"
        $startButton.Add_Click({ Start-Installation -StartButton $startButton })
        $script:MainForm.Controls.Add($startButton)

        # Show form
        [System.Windows.Forms.Application]::Run($script:MainForm)
    }
    catch
    {
        $errorMsg = "Failed to initialize installer: $( $_.Exception.Message )"
        Write-Log -Message $errorMsg -Level "ERROR"
        Show-Error -Message $errorMsg
        Release-Mutex
        exit 1
    }
    finally
    {
        Write-Log -Message "=== iCamera Proxy Installer Ended ===" -Level "INFO"
        Release-Mutex
    }
}

# Add VB.NET for InputBox
Add-Type -AssemblyName Microsoft.VisualBasic

# Run main function
Main