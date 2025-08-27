# iCamera Proxy Installer - Technical Guide

## Architecture

### Core Components
- **PowerShell GUI**: Windows Forms-based interface
- **Dependency Manager**: Automated download and validation
- **Service Manager**: Windows service registration and control
- **Database Manager**: HSQLDB setup and configuration
- **Configuration Manager**: Dynamic file updates

### Key Functions

#### Installation Flow
```
Initialize-Logging → Test-AdminRights → Get-Configuration → 
Initialize-MainWindow → Start-Installation → Invoke-Step1-10
```

#### Uninstall Flow
```
Initialize-Logging → Test-AdminRights → Get-Configuration → 
Initialize-UninstallWindow → Start-UninstallProcess
```

## Configuration Schema

### installer.config.json Structure
```json
{
  "metadata": { "name", "version", "description" },
  "installation": { "totalSteps", "directoryName" },
  "requirements": { "minimumRamGB", "minimumDiskSpaceGB" },
  "dependencies": { "searchFolders", "packages" },
  "database": { "portRange", "name", "queries" },
  "services": { "hsqldb", "icameraproxy" },
  "application": { "files", "configurations" }
}
```

### Service Configuration
```json
{
  "name": "iCameraHSQLDB",
  "displayName": "iCamera HSQLDB Service",
  "mainClass": "org.hsqldb.server.Server",
  "jvmOptions": ["-Xms256m", "-Xmx512m"],
  "arguments": ["--props", "{install_path}\\{hsqldb_folder}\\server.properties"]
}
```

## Security Features

### File Integrity
- SHA256 validation for downloads
- Archive validation for ZIP files
- Executable version checking
- File lock detection and retry

### Permission Management
- Administrator privilege validation
- ACL permission setting for directories
- Service account configuration (LocalSystem)

### Path Validation
- Sanitized path construction
- Drive space validation
- Directory creation verification

## Error Handling

### Retry Logic
- Download failures: 3 attempts with exponential backoff
- File operations: 3 attempts with 2-second delays
- Service operations: Graceful degradation

### Logging Levels
- **INFO**: Normal operations
- **WARNING**: Non-critical issues
- **ERROR**: Critical failures requiring attention

### Recovery Mechanisms
- Automatic cleanup on failure
- Service rollback capabilities
- Temporary file cleanup

## Database Management

### Port Allocation
```powershell
Find-AvailablePort -StartPort 9001 -EndPort 9100
```

### Configuration Files
- `server.properties`: HSQLDB server configuration
- `sqltool.rc`: Connection profiles
- Database scripts: `create.script`, `insert.script`

### SQL Operations
```powershell
Execute-SqlScript -ScriptPath $path -RcFile $rcFile -ConnectionName "server_db"
Execute-SqlQuery -Query $sql -ConnectionName "server_db" -RcFile $rcFile
```

## Service Management

### Registration Process
1. Check existing service
2. Install new service (if needed)
3. Update configuration
4. Set failure recovery
5. Configure dependencies

### Service Dependencies
- iCameraProxy depends on iCameraHSQLDB
- Both services auto-start on boot
- Failure recovery: restart after 5/10/15 seconds

## GUI Framework

### Window Components
- Progress bar with step tracking
- Status label with color coding
- Log display with syntax highlighting
- Action buttons with state management

### Event Handling
- Thread-safe GUI updates
- Proper event cleanup
- Modal dialog management

## File Operations

### Extraction Logic
```powershell
Extract-Package -PackagePath $zip -DestinationPath $target -SevenZipPath $7z
Normalize-ExtractedPath -ExtractPath $target
```

### Path Normalization
- Handles nested archive structures
- Converts Windows/Unix path formats
- Resolves relative path references

## Dependency Management

### Search Strategy
1. Local file search in configured folders
2. Pattern matching with multiple extensions
3. Fallback to download if not found locally
4. Integrity validation before use

### Download Process
1. Multiple retry attempts
2. File size validation
3. SHA256 checksum verification
4. Temporary file cleanup

## Testing Framework

### Mock Functions
- Service simulation
- File operation mocking
- GUI testing without admin rights
- Progress tracking validation

### Test Scripts
- `test-uninstall.ps1`: GUI functionality testing
- `check-hsqldb.bat`: System validation
- `fix-hsqldb-service.ps1`: Diagnostic tool

## Performance Optimizations

### Batch Operations
- Multiple file reads in single call
- Grouped service operations
- Parallel dependency processing

### Memory Management
- Stream-based file operations
- Proper object disposal
- Garbage collection hints

### Network Efficiency
- Connection reuse
- Timeout management
- Bandwidth throttling

## Maintenance

### Log Rotation
- Daily log files with timestamps
- Automatic cleanup of old logs
- Size-based rotation triggers

### Update Mechanism
- Configuration-driven URLs
- Version checking capabilities
- Incremental update support

### Monitoring
- Service health checks
- Performance counters
- Event log integration

## Deployment

### Prerequisites
- PowerShell 5.1+
- .NET Framework 4.7.2+
- Windows Management Framework

### Distribution
- Single PowerShell script
- Embedded configuration
- Self-contained dependencies

### Automation
- Silent installation support
- Command-line parameter handling
- Exit code management