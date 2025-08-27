# Changelog

## [1.0.0] - 2025-08-28

### Added
- Initial release of iCamera Proxy Installer
- GUI-based installation with 10-step process
- Automatic dependency management and download
- HSQLDB database setup and configuration
- Windows service registration and management
- FileCatalyst HotFolder integration
- Comprehensive logging and error handling
- Uninstall functionality with GUI
- System requirements validation
- Drive selection and space checking
- Network connectivity testing
- File integrity validation with SHA256
- Service dependency management
- Configuration file templating
- Progress tracking and status updates

### Installation Features
- **Step 1**: Prerequisites check
- **Step 2**: Cleanup of previous installations
- **Step 3**: Drive selection and directory creation
- **Step 4**: System prechecks and validation
- **Step 5**: Dependency download and validation
- **Step 6**: Database setup and port allocation
- **Step 7**: FileCatalyst installation (conditional)
- **Step 8**: Application file setup
- **Step 9**: Windows service registration
- **Step 10**: Service startup and validation

### Dependencies Managed
- Amazon Corretto JRE 8
- HSQLDB 2.3.4
- Apache Commons Daemon 1.4.0+
- FFmpeg Release Essentials
- 7-Zip Standalone

### Services Created
- iCameraHSQLDB: Database service
- iCameraProxy: Main application service

### Configuration Files
- installer.config.json: Main configuration
- proxy-details.properties: Application settings
- logback.xml: Logging configuration
- server.properties: Database configuration
- sqltool.rc: Database connection profiles

### Security Features
- Administrator privilege validation
- File integrity checking with SHA256
- ACL permission management
- Service account configuration
- Path sanitization and validation

### Error Handling
- Retry logic for downloads and file operations
- Comprehensive logging with multiple levels
- Graceful error recovery and cleanup
- User-friendly error messages
- Detailed diagnostic information

### GUI Features
- Windows Forms-based interface
- Real-time progress tracking
- Color-coded log display
- Status updates and notifications
- Modal dialogs for user interaction
- Responsive design with anchoring

### Uninstall Features
- GUI-based uninstallation process
- Service stopping and removal
- File and directory cleanup
- Scheduled task removal
- Progress tracking and logging
- Comprehensive cleanup validation

### Testing
- Mock testing framework
- GUI functionality testing
- Service validation scripts
- Diagnostic and troubleshooting tools

### Documentation
- Comprehensive README
- Technical implementation guide
- Troubleshooting documentation
- Configuration reference
- API documentation