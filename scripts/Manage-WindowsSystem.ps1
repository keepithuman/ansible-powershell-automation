#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows System Management Script with Parameter Support

.DESCRIPTION
    This PowerShell script performs various Windows system management tasks including:
    - Service management (start, stop, restart, status)
    - Windows feature management
    - Event log analysis
    - System information gathering
    - File and folder operations
    - Registry operations

.PARAMETER Action
    The action to perform. Valid values: ServiceManagement, FeatureManagement, EventLogCheck, SystemInfo, FileOperations, RegistryCheck

.PARAMETER ServiceName
    Name of the Windows service to manage (required for ServiceManagement action)

.PARAMETER ServiceAction
    Action to perform on service: Start, Stop, Restart, Status

.PARAMETER FeatureName
    Name of Windows feature to enable/disable (required for FeatureManagement action)

.PARAMETER FeatureAction
    Action for Windows feature: Enable, Disable, Status

.PARAMETER LogName
    Event log name to analyze (default: System)

.PARAMETER EventLevel
    Event level to filter: Error, Warning, Information (default: Error)

.PARAMETER Hours
    Number of hours back to check events (default: 24)

.PARAMETER Path
    File or folder path for file operations

.PARAMETER RegistryPath
    Registry path to check or modify

.PARAMETER RegistryValue
    Registry value name

.PARAMETER OutputPath
    Path to save output files (default: C:\temp\ps-output)

.EXAMPLE
    .\Manage-WindowsSystem.ps1 -Action ServiceManagement -ServiceName "Spooler" -ServiceAction Status

.EXAMPLE
    .\Manage-WindowsSystem.ps1 -Action EventLogCheck -LogName Application -EventLevel Error -Hours 12

.EXAMPLE
    .\Manage-WindowsSystem.ps1 -Action SystemInfo -OutputPath "C:\Reports"

.EXAMPLE
    .\Manage-WindowsSystem.ps1 -Action FeatureManagement -FeatureName "IIS-WebServerRole" -FeatureAction Status
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("ServiceManagement", "FeatureManagement", "EventLogCheck", "SystemInfo", "FileOperations", "RegistryCheck")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$ServiceName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Start", "Stop", "Restart", "Status")]
    [string]$ServiceAction = "Status",
    
    [Parameter(Mandatory = $false)]
    [string]$FeatureName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Enable", "Disable", "Status")]
    [string]$FeatureAction = "Status",
    
    [Parameter(Mandatory = $false)]
    [string]$LogName = "System",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Error", "Warning", "Information")]
    [string]$EventLevel = "Error",
    
    [Parameter(Mandatory = $false)]
    [int]$Hours = 24,
    
    [Parameter(Mandatory = $false)]
    [string]$Path,
    
    [Parameter(Mandatory = $false)]
    [string]$RegistryPath,
    
    [Parameter(Mandatory = $false)]
    [string]$RegistryValue,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\temp\ps-output"
)

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $OutputPath "WindowsSystemManagement-$timestamp.log"

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

function Manage-WindowsService {
    param([string]$Name, [string]$Action)
    
    Write-Log "Managing service: $Name with action: $Action"
    
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        
        switch ($Action) {
            "Start" {
                if ($service.Status -eq "Stopped") {
                    Start-Service -Name $Name
                    Write-Log "Service $Name started successfully" "SUCCESS"
                } else {
                    Write-Log "Service $Name is already running" "INFO"
                }
            }
            "Stop" {
                if ($service.Status -eq "Running") {
                    Stop-Service -Name $Name -Force
                    Write-Log "Service $Name stopped successfully" "SUCCESS"
                } else {
                    Write-Log "Service $Name is already stopped" "INFO"
                }
            }
            "Restart" {
                Restart-Service -Name $Name -Force
                Write-Log "Service $Name restarted successfully" "SUCCESS"
            }
            "Status" {
                Write-Log "Service: $($service.Name), Status: $($service.Status), StartType: $($service.StartType)" "INFO"
            }
        }
        return $service
    }
    catch {
        Write-Log "Error managing service $Name`: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Manage-WindowsFeature {
    param([string]$Name, [string]$Action)
    
    Write-Log "Managing Windows feature: $Name with action: $Action"
    
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
        
        switch ($Action) {
            "Enable" {
                if ($feature.State -eq "Disabled") {
                    Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart
                    Write-Log "Feature $Name enabled successfully (restart may be required)" "SUCCESS"
                } else {
                    Write-Log "Feature $Name is already enabled" "INFO"
                }
            }
            "Disable" {
                if ($feature.State -eq "Enabled") {
                    Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart
                    Write-Log "Feature $Name disabled successfully (restart may be required)" "SUCCESS"
                } else {
                    Write-Log "Feature $Name is already disabled" "INFO"
                }
            }
            "Status" {
                Write-Log "Feature: $($feature.FeatureName), State: $($feature.State)" "INFO"
            }
        }
        return $feature
    }
    catch {
        Write-Log "Error managing feature $Name`: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Check-EventLogs {
    param([string]$LogName, [string]$Level, [int]$Hours)
    
    Write-Log "Checking $LogName event log for $Level events in last $Hours hours"
    
    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            Level = switch ($Level) {
                "Error" { 2 }
                "Warning" { 3 }
                "Information" { 4 }
            }
            StartTime = $startTime
        } -MaxEvents 50 -ErrorAction Stop
        
        Write-Log "Found $($events.Count) $Level events in $LogName log" "INFO"
        
        $reportPath = Join-Path $OutputPath "EventLog-$LogName-$Level-$timestamp.csv"
        $events | Select-Object TimeCreated, Id, LevelDisplayName, LogName, ProviderName, Message |
            Export-Csv -Path $reportPath -NoTypeInformation
        
        Write-Log "Event log report saved to: $reportPath" "SUCCESS"
        
        # Display top 5 events
        $events | Select-Object -First 5 | ForEach-Object {
            Write-Log "Event ID $($_.Id) at $($_.TimeCreated): $($_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)))..." "INFO"
        }
        
        return $events
    }
    catch {
        Write-Log "Error checking event logs: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-SystemInformation {
    Write-Log "Gathering system information"
    
    try {
        $systemInfo = @{
            ComputerName = $env:COMPUTERNAME
            Domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
            OS = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
            Architecture = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
            TotalMemoryGB = [Math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            Processor = (Get-WmiObject -Class Win32_Processor).Name
            LastBootTime = (Get-WmiObject -Class Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject -Class Win32_OperatingSystem).LastBootUpTime)
            CurrentUser = $env:USERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Timestamp = Get-Date
        }
        
        # Get disk information
        $diskInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
            @{
                Drive = $_.DeviceID
                SizeGB = [Math]::Round($_.Size / 1GB, 2)
                FreeSpaceGB = [Math]::Round($_.FreeSpace / 1GB, 2)
                PercentFree = [Math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
            }
        }
        
        # Get top 5 processes by CPU
        $topProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object {
            @{
                Name = $_.ProcessName
                CPU = $_.CPU
                WorkingSetMB = [Math]::Round($_.WorkingSet / 1MB, 2)
                Id = $_.Id
            }
        }
        
        $fullReport = @{
            SystemInfo = $systemInfo
            DiskInfo = $diskInfo
            TopProcesses = $topProcesses
        }
        
        # Save detailed report
        $reportPath = Join-Path $OutputPath "SystemInfo-$timestamp.json"
        $fullReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Log "System information report saved to: $reportPath" "SUCCESS"
        
        # Display summary
        Write-Log "Computer: $($systemInfo.ComputerName), OS: $($systemInfo.OS), Memory: $($systemInfo.TotalMemoryGB)GB" "INFO"
        $diskInfo | ForEach-Object {
            Write-Log "Drive $($_.Drive) - Size: $($_.SizeGB)GB, Free: $($_.FreeSpaceGB)GB ($($_.PercentFree)%)" "INFO"
        }
        
        return $fullReport
    }
    catch {
        Write-Log "Error gathering system information: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Perform-FileOperations {
    param([string]$Path)
    
    Write-Log "Performing file operations on path: $Path"
    
    try {
        if (Test-Path $Path) {
            $item = Get-Item $Path
            
            if ($item.PSIsContainer) {
                # Directory operations
                $dirInfo = @{
                    Path = $item.FullName
                    Created = $item.CreationTime
                    LastWrite = $item.LastWriteTime
                    FileCount = (Get-ChildItem $Path -File | Measure-Object).Count
                    SubdirCount = (Get-ChildItem $Path -Directory | Measure-Object).Count
                    TotalSizeMB = [Math]::Round((Get-ChildItem $Path -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
                }
                
                Write-Log "Directory: $($dirInfo.Path)" "INFO"
                Write-Log "Files: $($dirInfo.FileCount), Subdirectories: $($dirInfo.SubdirCount), Total Size: $($dirInfo.TotalSizeMB)MB" "INFO"
                
                # List top 10 largest files
                $largeFiles = Get-ChildItem $Path -Recurse -File | Sort-Object Length -Descending | Select-Object -First 10
                Write-Log "Top 10 largest files:" "INFO"
                $largeFiles | ForEach-Object {
                    Write-Log "  $($_.Name) - $([Math]::Round($_.Length / 1KB, 2))KB" "INFO"
                }
                
                return $dirInfo
            } else {
                # File operations
                $fileInfo = @{
                    Path = $item.FullName
                    SizeKB = [Math]::Round($item.Length / 1KB, 2)
                    Created = $item.CreationTime
                    LastWrite = $item.LastWriteTime
                    Extension = $item.Extension
                    ReadOnly = $item.IsReadOnly
                }
                
                Write-Log "File: $($fileInfo.Path), Size: $($fileInfo.SizeKB)KB, Extension: $($fileInfo.Extension)" "INFO"
                return $fileInfo
            }
        } else {
            Write-Log "Path does not exist: $Path" "ERROR"
            return $null
        }
    }
    catch {
        Write-Log "Error performing file operations: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Check-Registry {
    param([string]$Path, [string]$ValueName)
    
    Write-Log "Checking registry path: $Path"
    
    try {
        if (Test-Path $Path) {
            $regKey = Get-Item $Path
            $values = $regKey.GetValueNames()
            
            Write-Log "Registry key exists with $($values.Count) values" "INFO"
            
            if ($ValueName) {
                if ($ValueName -in $values) {
                    $value = Get-ItemProperty -Path $Path -Name $ValueName
                    Write-Log "Registry value '$ValueName' = '$($value.$ValueName)'" "INFO"
                    return @{ Key = $Path; Value = $ValueName; Data = $value.$ValueName }
                } else {
                    Write-Log "Registry value '$ValueName' not found" "ERROR"
                    return $null
                }
            } else {
                # List all values
                $values | ForEach-Object {
                    $val = Get-ItemProperty -Path $Path -Name $_
                    Write-Log "  $_ = $($val.$_)" "INFO"
                }
                return @{ Key = $Path; Values = $values }
            }
        } else {
            Write-Log "Registry path does not exist: $Path" "ERROR"
            return $null
        }
    }
    catch {
        Write-Log "Error checking registry: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Main execution logic
Write-Log "Starting Windows System Management Script" "INFO"
Write-Log "Action: $Action, Computer: $env:COMPUTERNAME, User: $env:USERNAME" "INFO"

$result = $null

switch ($Action) {
    "ServiceManagement" {
        if (-not $ServiceName) {
            Write-Log "ServiceName parameter is required for ServiceManagement action" "ERROR"
            exit 1
        }
        $result = Manage-WindowsService -Name $ServiceName -Action $ServiceAction
    }
    
    "FeatureManagement" {
        if (-not $FeatureName) {
            Write-Log "FeatureName parameter is required for FeatureManagement action" "ERROR"
            exit 1
        }
        $result = Manage-WindowsFeature -Name $FeatureName -Action $FeatureAction
    }
    
    "EventLogCheck" {
        $result = Check-EventLogs -LogName $LogName -Level $EventLevel -Hours $Hours
    }
    
    "SystemInfo" {
        $result = Get-SystemInformation
    }
    
    "FileOperations" {
        if (-not $Path) {
            Write-Log "Path parameter is required for FileOperations action" "ERROR"
            exit 1
        }
        $result = Perform-FileOperations -Path $Path
    }
    
    "RegistryCheck" {
        if (-not $RegistryPath) {
            Write-Log "RegistryPath parameter is required for RegistryCheck action" "ERROR"
            exit 1
        }
        $result = Check-Registry -Path $RegistryPath -ValueName $RegistryValue
    }
}

Write-Log "Script execution completed" "SUCCESS"
Write-Log "Log file saved to: $logFile" "INFO"

# Return result for programmatic use
return $result