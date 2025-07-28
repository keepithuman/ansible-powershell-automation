# Windows System Management PowerShell Scripts

This repository contains PowerShell scripts for Windows system administration and automation tasks.

## Scripts

### Manage-WindowsSystem.ps1

A comprehensive PowerShell script that performs various Windows system management tasks with parameter support.

**Features:**
- Service management (start, stop, restart, status)
- Windows feature management (enable/disable features)
- Event log analysis and reporting
- System information gathering
- File and folder operations
- Registry operations
- Comprehensive logging and error handling

**Requirements:**
- PowerShell 5.1 or higher
- Administrator privileges (script will enforce this)
- Windows 10/Server 2016 or higher

## Usage Examples

### Service Management
```powershell
# Check service status
.\scripts\Manage-WindowsSystem.ps1 -Action ServiceManagement -ServiceName "Spooler" -ServiceAction Status

# Start a service
.\scripts\Manage-WindowsSystem.ps1 -Action ServiceManagement -ServiceName "Spooler" -ServiceAction Start

# Stop a service
.\scripts\Manage-WindowsSystem.ps1 -Action ServiceManagement -ServiceName "Spooler" -ServiceAction Stop

# Restart a service
.\scripts\Manage-WindowsSystem.ps1 -Action ServiceManagement -ServiceName "Spooler" -ServiceAction Restart
```

### Windows Feature Management
```powershell
# Check IIS feature status
.\scripts\Manage-WindowsSystem.ps1 -Action FeatureManagement -FeatureName "IIS-WebServerRole" -FeatureAction Status

# Enable Hyper-V feature
.\scripts\Manage-WindowsSystem.ps1 -Action FeatureManagement -FeatureName "Microsoft-Hyper-V-All" -FeatureAction Enable

# Disable Windows Media Player
.\scripts\Manage-WindowsSystem.ps1 -Action FeatureManagement -FeatureName "WindowsMediaPlayer" -FeatureAction Disable
```

### Event Log Analysis
```powershell
# Check last 24 hours of system errors
.\scripts\Manage-WindowsSystem.ps1 -Action EventLogCheck -LogName System -EventLevel Error -Hours 24

# Check application warnings in last 12 hours
.\scripts\Manage-WindowsSystem.ps1 -Action EventLogCheck -LogName Application -EventLevel Warning -Hours 12

# Check security events
.\scripts\Manage-WindowsSystem.ps1 -Action EventLogCheck -LogName Security -EventLevel Information -Hours 6
```

### System Information
```powershell
# Gather comprehensive system information
.\scripts\Manage-WindowsSystem.ps1 -Action SystemInfo

# Save report to custom location
.\scripts\Manage-WindowsSystem.ps1 -Action SystemInfo -OutputPath "C:\Reports"
```

### File Operations
```powershell
# Analyze a directory
.\scripts\Manage-WindowsSystem.ps1 -Action FileOperations -Path "C:\Windows\System32"

# Get information about a specific file
.\scripts\Manage-WindowsSystem.ps1 -Action FileOperations -Path "C:\Windows\System32\notepad.exe"

# Analyze user directory
.\scripts\Manage-WindowsSystem.ps1 -Action FileOperations -Path "C:\Users\$env:USERNAME\Documents"
```

### Registry Operations
```powershell
# Check a registry key
.\scripts\Manage-WindowsSystem.ps1 -Action RegistryCheck -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

# Check specific registry value
.\scripts\Manage-WindowsSystem.ps1 -Action RegistryCheck -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -RegistryValue "ProgramFilesDir"

# Check Windows version info
.\scripts\Manage-WindowsSystem.ps1 -Action RegistryCheck -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -RegistryValue "ProductName"
```

## Remote Execution

You can download and execute the script directly from GitHub:

```powershell
# Download and execute in one command
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/keepithuman/ansible-powershell-automation/main/scripts/Manage-WindowsSystem.ps1" -UseBasicParsing).Content

# Or download first, then execute
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/keepithuman/ansible-powershell-automation/main/scripts/Manage-WindowsSystem.ps1" -OutFile "C:\temp\Manage-WindowsSystem.ps1"
.\C:\temp\Manage-WindowsSystem.ps1 -Action SystemInfo
```

## Output and Logging

The script creates comprehensive logs and reports:

- **Log files**: Saved to `C:\temp\ps-output\WindowsSystemManagement-[timestamp].log`
- **Reports**: JSON and CSV files for detailed analysis
- **Console output**: Real-time status and results

You can customize the output location with the `-OutputPath` parameter.

## Common Windows Features

Here are some commonly managed Windows features:

| Feature Name | Description |
|--------------|-------------|
| IIS-WebServerRole | Internet Information Services (IIS) |
| Microsoft-Hyper-V-All | Hyper-V Platform |
| TelnetClient | Telnet Client |
| TFTP | TFTP Client |
| WindowsMediaPlayer | Windows Media Player |
| WorkFolders-Client | Work Folders Client |
| Printing-Foundation-Features | Windows Fax and Scan |

## Common Windows Services

Here are some commonly managed services:

| Service Name | Description |
|--------------|-------------|
| Spooler | Print Spooler |
| BITS | Background Intelligent Transfer Service |
| Themes | Themes Service |
| AudioSrv | Windows Audio |
| EventLog | Windows Event Log |
| W32Time | Windows Time |
| WinRM | Windows Remote Management |

## Error Handling

The script includes comprehensive error handling and will:
- Log all errors to the log file
- Continue execution where possible
- Provide meaningful error messages
- Return appropriate exit codes for automation

## Security Notes

- Script requires administrator privileges
- Uses PowerShell execution policy bypass for process scope only
- All operations are logged for audit purposes
- No sensitive information is stored in plain text

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is open source and available under the MIT License.