# User Stories - iCamera Proxy Installer

## Story 1: System Administrator - Fresh Installation
**As a** system administrator  
**I want to** install iCamera Proxy on a new Windows server  
**So that** I can deploy the camera management system quickly and reliably  

### Acceptance Criteria
- [ ] Installer validates system requirements (8GB RAM, 2GB disk space)
- [ ] All dependencies are automatically downloaded and installed
- [ ] Database is configured with available port (9001-9100)
- [ ] Windows services are registered and started automatically
- [ ] Installation completes with success confirmation
- [ ] Log files are created for troubleshooting

### Definition of Done
- Services "iCameraHSQLDB" and "iCameraProxy" are running
- Application accessible via configured database port
- All files installed in C:\iCamera directory
- Installation log shows no errors

---

## Story 2: IT Support Technician - System Maintenance
**As an** IT support technician  
**I want to** uninstall iCamera Proxy cleanly from a system  
**So that** I can remove the software completely without leaving residual files  

### Acceptance Criteria
- [ ] Uninstaller stops all running services gracefully
- [ ] All installation files and directories are removed
- [ ] Windows services are unregistered from system
- [ ] Scheduled tasks are cleaned up
- [ ] Progress is shown during uninstallation process
- [ ] Confirmation message displays successful removal

### Definition of Done
- No iCamera services remain in Windows Services
- C:\iCamera directory is completely removed
- No scheduled tasks related to iCamera exist
- Uninstall log confirms complete removal

---

## Story 3: Database Administrator - Configuration Management
**As a** database administrator  
**I want to** have the installer automatically configure HSQLDB with proper settings  
**So that** the database is ready for production use without manual setup  

### Acceptance Criteria
- [ ] Installer finds available port in range 9001-9100
- [ ] Database server.properties file is created with correct settings
- [ ] SQL scripts are executed to create database structure
- [ ] Database connection profiles (sqltool.rc) are configured
- [ ] Database service starts automatically after installation
- [ ] Database manager tool is available for administration

### Definition of Done
- HSQLDB service is running on allocated port
- Database responds to connection attempts
- All required tables and data are present
- Database manager GUI can connect successfully

---

## Story 4: Application Developer - Dependency Management
**As an** application developer  
**I want to** have all required dependencies automatically managed  
**So that** I don't need to manually install Java, FFmpeg, and other components  

### Acceptance Criteria
- [ ] Java Runtime Environment (JRE 8) is downloaded and installed
- [ ] FFmpeg binaries are extracted and configured
- [ ] Apache Commons Daemon (procrun) is set up for service management
- [ ] File integrity is validated using SHA256 checksums
- [ ] Local files are used if available to avoid re-downloading
- [ ] All dependencies are properly integrated with main application

### Definition of Done
- Java executable is available at C:\iCamera\jre\bin\java.exe
- FFmpeg is accessible at C:\iCamera\ffmpeg\bin\ffmpeg.exe
- Services can start using procrun wrapper
- Application configuration points to correct dependency paths