# iCamera Proxy Installer

## Overview
GUI-based installer for iCamera Proxy system with automatic dependency management, database setup, and Windows service configuration.

## System Requirements
- Windows 10/11 or Windows Server 2016+
- 8GB RAM minimum
- 2GB free disk space
- Administrator privileges
- Internet connectivity (for downloads)

## Quick Start
```powershell
# Install
.\iCameraProxyInstaller.ps1

# Uninstall
.\iCameraProxyInstaller.ps1 -Uninstall
```

## Installation Process

### Step 1: Prerequisites Check
- Validates system requirements
- Checks RAM and disk space
- Tests network connectivity

### Step 2: Cleanup
- Removes previous installations
- Cleans up scheduled tasks

### Step 3: Drive Selection
- Auto-selects single drive
- Prompts for drive selection (multiple drives)
- Creates installation directory

### Step 4: System Prechecks
- Final validation of requirements
- Network connectivity tests

### Step 5: Dependencies
Downloads and installs:
- Java Runtime Environment (JRE 8)
- HSQLDB 2.3.4
- Apache Commons Daemon (procrun)
- FFmpeg Essentials
- 7-Zip (for extraction)

### Step 6: Database Setup
- Finds available port (9001-9100)
- Creates database structure
- Executes SQL scripts
- Configures connection settings

### Step 7: FileCatalyst (Optional)
- Installs if required by database config
- Configures hotfolder integration

### Step 8: Application Setup
- Copies application files
- Updates configuration files
- Creates log directories

### Step 9: Service Registration
- Registers Windows services:
  - iCameraHSQLDB (database)
  - iCameraProxy (application)

### Step 10: Service Startup
- Starts services
- Validates operation
- Shows completion status

## Configuration Files

### installer.config.json
Main configuration with:
- System requirements
- Dependency URLs and checksums
- Database settings
- Service configurations

### proxy-details.properties
Application configuration:
- Database connection
- FileCatalyst paths
- FFmpeg location

### logback.xml
Logging configuration

## Services Created
- **iCameraHSQLDB**: Database service (port 9001-9100)
- **iCameraProxy**: Main application service

## Directory Structure
```
C:\iCamera\
├── jre\              # Java Runtime
├── hsqldb\           # Database files
├── procrun\          # Service wrapper
├── ffmpeg\           # Media processing
├── app\              # Application files
└── logs\             # Log files
```

## Uninstallation
- Stops and removes services
- Removes scheduled tasks
- Deletes installation files
- GUI progress tracking

## Troubleshooting

### Service Won't Start
1. Check log files in `C:\iCamera\logs\`
2. Verify Java installation
3. Ensure database files exist
4. Check port availability

### Installation Fails
1. Run as Administrator
2. Check system requirements
3. Verify internet connectivity
4. Review installer log file

### Database Issues
1. Check server.properties file
2. Verify port not in use
3. Test Java classpath
4. Review HSQLDB logs

## Log Files
- `installer_YYYYMMDD.log`: Installation log
- `hsqldb-stdout.log`: Database output
- `hsqldb-stderr.log`: Database errors
- `icamera-stdout.log`: Application output
- `icamera-stderr.log`: Application errors

## Command Line Options
```powershell
# Standard installation
.\iCameraProxyInstaller.ps1

# Uninstall mode
.\iCameraProxyInstaller.ps1 -Uninstall
```

## Dependencies
All dependencies are automatically downloaded:
- Amazon Corretto JRE 8
- HSQLDB 2.3.4
- Apache Commons Daemon 1.4.0+
- FFmpeg Release Essentials
- 7-Zip Standalone

## Network Requirements
Installer connects to:
- https://corretto.aws (JRE download)
- https://master.dl.sourceforge.net (HSQLDB)
- https://downloads.apache.org (Commons Daemon)
- https://www.gyan.dev (FFmpeg)
- https://www.7-zip.org (7-Zip)

## Support
Check log files for detailed error information. Common issues are resolved by:
1. Running as Administrator
2. Ensuring system requirements are met
3. Verifying network connectivity
4. Checking antivirus exclusions