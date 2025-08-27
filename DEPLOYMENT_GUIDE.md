# Deployment Guide

## Pre-Deployment Checklist

### System Requirements
- [ ] Windows 10/11 or Windows Server 2016+
- [ ] 8GB RAM minimum
- [ ] 2GB free disk space
- [ ] Administrator privileges
- [ ] Internet connectivity
- [ ] PowerShell 5.1+
- [ ] .NET Framework 4.7.2+

### Network Requirements
- [ ] Access to download URLs:
  - corretto.aws (JRE)
  - sourceforge.net (HSQLDB)
  - apache.org (Commons Daemon)
  - gyan.dev (FFmpeg)
  - 7-zip.org (7-Zip)
- [ ] Ports 9001-9100 available for database

## Deployment Methods

### Method 1: Direct Execution
```powershell
# Copy installer files to target system
# Run as Administrator
.\iCameraProxyInstaller.ps1
```

### Method 2: Network Deployment
```powershell
# From network share
\\server\share\iCameraProxyInstaller.ps1

# With UNC path support
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
& "\\server\share\iCameraProxyInstaller.ps1"
```

### Method 3: Automated Deployment
```batch
@echo off
powershell.exe -ExecutionPolicy Bypass -File "iCameraProxyInstaller.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo Installation failed with error code %ERRORLEVEL%
    pause
    exit /b %ERRORLEVEL%
)
echo Installation completed successfully
```

## File Distribution

### Required Files
```
iCameraProxyInstaller.ps1    # Main installer script
installer.config.json        # Configuration file
CameraProxy.jar             # Application JAR
proxy-details.properties    # Application config
logback.xml                 # Logging config
CameraProxy.sql             # Database script
database-scripts/           # Database initialization
├── create.script
├── db0.script
└── insert.script
```

### Optional Files (Auto-downloaded)
```
7zr.exe                     # 7-Zip standalone
amazon-corretto-8-x64-windows-jre.zip
hsqldb-2.3.4.zip
commons-daemon-1.4.0-bin-windows.zip
ffmpeg-release-essentials.7z
install_fc_hotfolder.exe    # FileCatalyst installer
```

## Configuration Customization

### Pre-Installation Setup
```json
{
  "installation": {
    "directoryName": "iCamera"  // Change install folder
  },
  "requirements": {
    "minimumRamGB": 8,          // Adjust RAM requirement
    "minimumDiskSpaceGB": 2     // Adjust disk space
  },
  "database": {
    "portRange": {
      "start": 9001,            // Change port range
      "end": 9100
    }
  }
}
```

### Network Configuration
```json
{
  "requirements": {
    "connectivityUrls": [
      "https://your-internal-server.com",  // Add internal URLs
      "https://g01.tcsion.com",
      "https://cctv4.tcsion.com"
    ]
  }
}
```

## Silent Installation

### Unattended Mode
```powershell
# Modify installer for silent mode
$script:SilentMode = $true

# Skip user prompts
if (-not $script:SilentMode) {
    # User interaction code
}
```

### Batch Deployment
```batch
@echo off
setlocal enabledelayedexpansion

set INSTALL_LOG=deployment_%DATE:~-4,4%%DATE:~-10,2%%DATE:~-7,2%.log

echo Starting iCamera Proxy deployment... > %INSTALL_LOG%
echo Timestamp: %DATE% %TIME% >> %INSTALL_LOG%

powershell.exe -ExecutionPolicy Bypass -File "iCameraProxyInstaller.ps1" >> %INSTALL_LOG% 2>&1

if %ERRORLEVEL% EQU 0 (
    echo SUCCESS: Installation completed >> %INSTALL_LOG%
    exit /b 0
) else (
    echo ERROR: Installation failed with code %ERRORLEVEL% >> %INSTALL_LOG%
    exit /b %ERRORLEVEL%
)
```

## Post-Deployment Validation

### Service Verification
```powershell
# Check services are running
Get-Service -Name "iCameraHSQLDB", "iCameraProxy" | Format-Table Name, Status, StartType

# Test database connectivity
Test-NetConnection -ComputerName localhost -Port 9001

# Verify log files
Get-ChildItem "C:\iCamera\logs\" -Name "*.log"
```

### Health Check Script
```powershell
# Create health check script
$healthCheck = @"
# iCamera Health Check
`$services = Get-Service -Name "iCameraHSQLDB", "iCameraProxy"
`$allRunning = (`$services | Where-Object Status -ne "Running").Count -eq 0

if (`$allRunning) {
    Write-Host "✓ All services running" -ForegroundColor Green
    exit 0
} else {
    Write-Host "✗ Service issues detected" -ForegroundColor Red
    `$services | Format-Table Name, Status
    exit 1
}
"@

$healthCheck | Out-File "C:\iCamera\health-check.ps1"
```

## Troubleshooting Deployment

### Common Issues

#### Permission Errors
```powershell
# Fix: Run as Administrator
# Verify with:
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
```

#### Network Connectivity
```powershell
# Test connectivity
Test-NetConnection -ComputerName "corretto.aws" -Port 443
Test-NetConnection -ComputerName "sourceforge.net" -Port 443
```

#### Port Conflicts
```powershell
# Check port availability
Get-NetTCPConnection -LocalPort 9001 -ErrorAction SilentlyContinue
```

#### Service Startup Issues
```powershell
# Check service logs
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10
```

## Rollback Procedures

### Manual Rollback
```powershell
# Stop services
Stop-Service -Name "iCameraProxy", "iCameraHSQLDB" -Force

# Remove services
sc.exe delete "iCameraProxy"
sc.exe delete "iCameraHSQLDB"

# Remove files
Remove-Item "C:\iCamera" -Recurse -Force
```

### Automated Rollback
```powershell
# Use uninstaller
.\iCameraProxyInstaller.ps1 -Uninstall
```

## Monitoring and Maintenance

### Log Monitoring
```powershell
# Monitor installation logs
Get-Content "C:\iCamera\logs\*.log" -Tail 50 -Wait

# Archive old logs
Get-ChildItem "C:\iCamera\logs\" -Filter "*.log" | 
Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) |
Compress-Archive -DestinationPath "C:\iCamera\logs\archive.zip"
```

### Performance Monitoring
```powershell
# Monitor service performance
Get-Counter "\Process(java)\% Processor Time"
Get-Counter "\Process(java)\Working Set"
```

### Update Procedures
1. Stop services
2. Backup configuration files
3. Run new installer
4. Verify configuration
5. Start services
6. Validate functionality

## Security Considerations

### Firewall Configuration
```powershell
# Allow database port
New-NetFirewallRule -DisplayName "iCamera HSQLDB" -Direction Inbound -Protocol TCP -LocalPort 9001 -Action Allow
```

### Service Account Security
- Services run as LocalSystem by default
- Consider dedicated service account for production
- Apply principle of least privilege

### File System Security
- Installation directory has restricted access
- Log files readable by administrators only
- Configuration files protected from modification

## Documentation Handover

### Provide to Operations Team
- [ ] README.md - User guide
- [ ] TECHNICAL_GUIDE.md - Technical details
- [ ] This deployment guide
- [ ] Log file locations
- [ ] Service management procedures
- [ ] Troubleshooting contacts