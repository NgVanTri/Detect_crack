<# 
    scan_vt.ps1 (v3) - PowerShell 5.1
    Inventory -> Compliance score
    Indicators -> Crack score
    Conditional enrichment -> Kaspersky OpenTIP
    Output: Windows Event Log + File Log
#>

# =========================
# CONFIG
# =========================
$Config = @{
    # Event Log Configuration
    EventLogSource = "WazuhCrackAudit"
    EventLogName = "Application"
    
    # File Log Configuration (backup)
    FileLogPath = "C:\ProgramData\wazuh-crack-audit.json"
    MaxLogBytes = 5MB
    
    # API Configuration
    OpenTIPApiKey = if ($env:OPENTIP_APIKEY) { $env:OPENTIP_APIKEY } else { "" }
    
    # Scoring Configuration
    ComplianceHigh = 6
    CrackHigh = 10
    CrackMed = 6
    EnrichMinCrackScore = 10
    
    # Weights
    Weights = @{
        UnknownPublisher = 2
        UnauthorizedApp = 4
        KmsHostNonApproved = 10
        SuspTask = 5
        SuspService = 5
        SuspFileName = 4
    }
    
    # Allow Lists
    AllowVendors = @(
        "Microsoft", "Google", "Mozilla", "Intel", "Dell", "HP", "Lenovo", "Adobe",
        "The Apache Software Foundation", "Igor Pavlov", "Audacity Team", "Foxit Software",
        "JetBrains", "Garena", "Coc Coc", "C?c C?c", "Hex-Rays"
    )
    
    AllowKmsHosts = @(
        # "kms.company.local"
    )
    
    # Keywords for detection
    CrackKeywords = '(?i)\b(kms|autokms|kmspico|vlmcs|kmsauto|kms-service|keygen|crack|patch|loader|activator|chew\-wga|mstoolkit)\b'
    
    # Hot folders for suspicious files
    HotFolders = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop", 
        "$env:TEMP",
        "$env:ProgramData"
    )
    
    # Whitelists
    WhitelistTasks = @(
        @{ TaskPath = '\Microsoft\Windows\WindowsColorSystem\'; TaskName = 'Calibration Loader' }
    )
    
    WhitelistServices = @(
        'jhi_service',  # Intel
        'wlidsvc'       # Microsoft Account
    )
    
    # Output limits
    MaxItems = @{
        Apps = 10
        Tasks = 10
        Services = 10
        Files = 10
        Enrich = 5
    }
}

# =========================
# EVENT LOG FUNCTIONS
# =========================
function Initialize-EventLog {
    param(
        [string]$SourceName = $Config.EventLogSource,
        [string]$LogName = $Config.EventLogName
    )
    
    # Check if source exists, create if not
    if (-not [System.Diagnostics.EventLog]::SourceExists($SourceName)) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource($SourceName, $LogName)
            Write-Verbose "Created Event Log source: $SourceName"
        }
        catch {
            Write-Warning "Failed to create Event Log source: $_"
            return $false
        }
    }
    return $true
}

function Write-EventLogEntry {
    param(
        [string]$Message,
        [int]$EventID = 1001,
        [ValidateSet("Information", "Warning", "Error")] 
        [string]$EntryType = "Information",
        [string]$SourceName = $Config.EventLogSource
    )
    
    try {
        Write-EventLog -LogName $Config.EventLogName -Source $SourceName `
            -EventId $EventID -EntryType $EntryType -Message $Message
        return $true
    }
    catch {
        Write-Warning "Failed to write to Event Log: $_"
        return $false
    }
}

# =========================
# HELPER FUNCTIONS
# =========================
function Get-InstalledApps {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $apps = @()
    foreach ($p in $paths) {
        try {
            $apps += Get-ItemProperty $p -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, Publisher, DisplayVersion, InstallLocation
        }
        catch { }
    }
    
    return $apps | Sort-Object DisplayName, Publisher, DisplayVersion -Unique
}

function Get-SuspiciousFiles {
    param([array]$Folders = $Config.HotFolders)
    
    $results = @()
    foreach ($folder in $Folders) {
        if (-not (Test-Path $folder)) { continue }
        
        try {
            # Scan first level files
            $files = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ($file.Name -match $Config.CrackKeywords) {
                    $results += [PSCustomObject]@{
                        Name = $file.Name
                        Path = $file.FullName
                        Size = $file.Length
                        LastModified = $file.LastWriteTimeUtc.ToString("o")
                    }
                }
            }
            
            # Scan one level deep
            $subdirs = Get-ChildItem -Path $folder -Directory -ErrorAction SilentlyContinue
            foreach ($subdir in $subdirs) {
                $subfiles = Get-ChildItem -Path $subdir.FullName -File -ErrorAction SilentlyContinue
                foreach ($file in $subfiles) {
                    if ($file.Name -match $Config.CrackKeywords) {
                        $results += [PSCustomObject]@{
                            Name = $file.Name
                            Path = $file.FullName
                            Size = $file.Length
                            LastModified = $file.LastWriteTimeUtc.ToString("o")
                        }
                    }
                }
            }
        }
        catch { }
    }
    
    return $results
}

function Get-SuspiciousTasks {
    $results = @()
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            # Skip whitelisted tasks
            $isWhitelisted = $false
            foreach ($white in $Config.WhitelistTasks) {
                if ($task.TaskPath -eq $white.TaskPath -and $task.TaskName -eq $white.TaskName) {
                    $isWhitelisted = $true
                    break
                }
            }
            if ($isWhitelisted) { continue }
            
            # Check for keywords
            $matched = $false
            if ($task.TaskName -match $Config.CrackKeywords -or 
                $task.TaskPath -match $Config.CrackKeywords) {
                $matched = $true
            }
            
            # Check actions
            $suspiciousActions = @()
            foreach ($action in $task.Actions) {
                $actionString = "$($action.Execute) $($action.Arguments)"
                if ($actionString -match $Config.CrackKeywords) {
                    $matched = $true
                    $suspiciousActions += @{
                        Execute = $action.Execute
                        Arguments = $action.Arguments
                    }
                }
            }
            
            if ($matched) {
                $results += [PSCustomObject]@{
                    Name = $task.TaskName
                    Path = $task.TaskPath
                    State = $task.State
                    Actions = $suspiciousActions
                }
            }
        }
    }
    catch { }
    
    return $results
}

function Get-SuspiciousServices {
    $results = @()
    
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($service in $services) {
            # Skip whitelisted
            if ($Config.WhitelistServices -contains $service.Name) { continue }
            
            # Check for keywords
            if ($service.Name -match $Config.CrackKeywords -or 
                $service.DisplayName -match $Config.CrackKeywords -or
                $service.PathName -match $Config.CrackKeywords) {
                
                $results += [PSCustomObject]@{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    State = $service.State
                    PathName = $service.PathName
                    StartMode = $service.StartMode
                }
            }
        }
    }
    catch { }
    
    return $results
}

function Get-LicensingInfo {
    try {
        $licensing = Get-CimInstance SoftwareLicensingProduct -ErrorAction SilentlyContinue |
            Where-Object { 
                ($_.Name -like "*Windows*" -or $_.Name -like "*Office*") -and 
                $_.PartialProductKey 
            } |
            Select-Object Name, LicenseStatus, Description, PartialProductKey
        
        $service = Get-CimInstance SoftwareLicensingService -ErrorAction SilentlyContinue |
            Select-Object KeyManagementServiceMachine, KeyManagementServicePort,
                        DiscoveredKeyManagementServiceMachineName,
                        DiscoveredKeyManagementServiceMachinePort,
                        ClientMachineID
        
        return @{
            Products = $licensing
            Service = $service
        }
    }
    catch {
        return @{}
    }
}

function Invoke-KasperskyLookup {
    param(
        [string]$Hash,
        [string]$ApiKey = $Config.OpenTIPApiKey
    )
    
    if ([string]::IsNullOrWhiteSpace($ApiKey) -or [string]::IsNullOrWhiteSpace($Hash)) {
        return $null
    }
    
    try {
        $uri = "https://opentip.kaspersky.com/api/v1/search/hash?request=$Hash"
        $headers = @{ "x-api-key" = $ApiKey }
        
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -TimeoutSec 15
        return $response
    }
    catch {
        return $null
    }
}

# =========================
# MAIN AUDIT FUNCTION
# =========================
function Invoke-SecurityAudit {
    # Initialize event log
    if (-not (Initialize-EventLog)) {
        Write-Error "Failed to initialize Event Log. Script cannot continue."
        return
    }
    
    # Collect data
    Write-Verbose "Collecting system information..."
    
    # 1. Installed Applications
    $apps = Get-InstalledApps
    $complianceScore = 0
    $complianceReasons = @()
    $unauthorizedApps = @()
    $unknownPublisherApps = @()
    
    foreach ($app in $apps) {
        $pub = [string]$app.Publisher
        
        if ([string]::IsNullOrWhiteSpace($pub)) {
            $unknownPublisherApps += $app
            continue
        }
        
        $isApproved = $false
        foreach ($vendor in $Config.AllowVendors) {
            if ($pub -like "*$vendor*") {
                $isApproved = $true
                break
            }
        }
        
        if (-not $isApproved) {
            $unauthorizedApps += $app
        }
    }
    
    # Calculate compliance score
    if ($unauthorizedApps.Count -gt 0) {
        $complianceScore += $Config.Weights.UnauthorizedApp
        $complianceReasons += "Unauthorized publisher apps detected"
    }
    
    if ($unknownPublisherApps.Count -gt 0) {
        $complianceScore += $Config.Weights.UnknownPublisher
        $complianceReasons += "Apps with missing publisher info"
    }
    
    # 2. Crack Indicators
    Write-Verbose "Scanning for crack indicators..."
    $crackScore = 0
    $crackReasons = @()
    $indicators = @{
        Licensing = @{}
        Tasks = @()
        Services = @()
        Files = @()
    }
    
    # Licensing check
    $licenseInfo = Get-LicensingInfo
    $indicators.Licensing = $licenseInfo
    
    if ($licenseInfo.Service) {
        $kmsHost = $licenseInfo.Service.KeyManagementServiceMachine
        if (-not [string]::IsNullOrWhiteSpace($kmsHost)) {
            $isApproved = $false
            foreach ($allowed in $Config.AllowKmsHosts) {
                if ($kmsHost -ieq $allowed) {
                    $isApproved = $true
                    break
                }
            }
            
            if (-not $isApproved) {
                $crackScore += $Config.Weights.KmsHostNonApproved
                $crackReasons += "Non-approved KMS host: $kmsHost"
            }
        }
    }
    
    # Suspicious tasks
    $suspTasks = Get-SuspiciousTasks | Select-Object -First $Config.MaxItems.Tasks
    $indicators.Tasks = $suspTasks
    
    if ($suspTasks.Count -gt 0) {
        $crackScore += $Config.Weights.SuspTask
        $crackReasons += "Suspicious scheduled tasks found"
    }
    
    # Suspicious services
    $suspServices = Get-SuspiciousServices | Select-Object -First $Config.MaxItems.Services
    $indicators.Services = $suspServices
    
    if ($suspServices.Count -gt 0) {
        $crackScore += $Config.Weights.SuspService
        $crackReasons += "Suspicious services found"
    }
    
    # Suspicious files
    $suspFiles = Get-SuspiciousFiles | Select-Object -First $Config.MaxItems.Files
    $indicators.Files = $suspFiles
    
    if ($suspFiles.Count -gt 0) {
        $crackScore += $Config.Weights.SuspFileName
        $crackReasons += "Suspicious files found in hot folders"
    }
    
    # 3. Determine severity
    $complianceSeverity = "low"
    if ($complianceScore -ge $Config.ComplianceHigh) { $complianceSeverity = "high" }
    elseif ($complianceScore -ge 3) { $complianceSeverity = "medium" }
    
    $crackSeverity = "low"
    if ($crackScore -ge $Config.CrackHigh) { $crackSeverity = "high" }
    elseif ($crackScore -ge $Config.CrackMed) { $crackSeverity = "medium" }
    
    # 4. Enrichment (if needed)
    $enrichment = @{}
    if ($crackScore -ge $Config.EnrichMinCrackScore -and 
        -not [string]::IsNullOrWhiteSpace($Config.OpenTIPApiKey)) {
        
        Write-Verbose "Performing enrichment with Kaspersky OpenTIP..."
        $enrichedFiles = @()
        $count = 0
        
        foreach ($file in $suspFiles) {
            if ($count -ge $Config.MaxItems.Enrich) { break }
            
            try {
                $hash = Get-FileHash -Path $file.Path -Algorithm SHA256 -ErrorAction Stop
                $result = Invoke-KasperskyLookup -Hash $hash.Hash
                
                if ($result) {
                    $enrichedFiles += @{
                        Path = $file.Path
                        SHA256 = $hash.Hash
                        Zone = $result.Zone
                        FileStatus = $result.FileGeneralInfo.FileStatus
                        Verdict = $result.FileGeneralInfo.Verdict
                        LastAnalysis = (Get-Date).ToString("o")
                    }
                }
            }
            catch {
                # Silently continue
            }
            
            $count++
        }
        
        if ($enrichedFiles.Count -gt 0) {
            $enrichment.Kaspersky = $enrichedFiles
        }
    }
    
    # 5. Prepare final event
    $eventData = @{
        timestamp = (Get-Date).ToString("o")
        type = "crack_audit_v3"
        host = $env:COMPUTERNAME
        user = "$env:USERDOMAIN\$env:USERNAME"
        
        scores = @{
            compliance = @{
                value = $complianceScore
                severity = $complianceSeverity
                reasons = $complianceReasons
            }
            crack = @{
                value = $crackScore
                severity = $crackSeverity
                reasons = $crackReasons
            }
        }
        
        indicators = @{
            unauthorized_apps = $unauthorizedApps | Select-Object -First $Config.MaxItems.Apps
            unknown_publisher_apps = $unknownPublisherApps | Select-Object -First $Config.MaxItems.Apps
            licensing = $indicators.Licensing
            suspicious_tasks = $indicators.Tasks
            suspicious_services = $indicators.Services
            suspicious_files = $indicators.Files
        }
        
        enrichment = $enrichment
        metadata = @{
            script_version = "3.0"
            scan_duration = "0"
            total_apps_scanned = $apps.Count
        }
    }
    
    # Convert to JSON for Event Log
    $jsonOutput = $eventData | ConvertTo-Json -Compress -Depth 10
    
    # Write to Event Log
    Write-Verbose "Writing to Event Log..."
    $logSuccess = Write-EventLogEntry -Message $jsonOutput -EventID 1001 -EntryType "Warning"
    
    # Also write to file (backup)
    try {
        $jsonOutput | Out-File -FilePath $Config.FileLogPath -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to file log: $_"
    }
    
    # Return summary
    return @{
        Success = $logSuccess
        Data = $eventData
        Summary = @"
Scan completed:
- Compliance: $complianceScore ($complianceSeverity)
- Crack: $crackScore ($crackSeverity)
- Total apps: $($apps.Count)
- Suspicious items: $($suspTasks.Count + $suspServices.Count + $suspFiles.Count)
- Event Log: $(if($logSuccess){'OK'}else{'Failed'})
"@
    }
}

# =========================
# EXECUTION
# =========================
try {
    # Suppress progress for cleaner output
    $ProgressPreference = 'SilentlyContinue'
    
    # Run the audit
    $result = Invoke-SecurityAudit
    
    # Output summary
    if ($result.Success) {
        Write-Host "`n=== Security Audit Complete ===" -ForegroundColor Green
        Write-Host $result.Summary
        Write-Host "`nEvent written to: $($Config.EventLogName)/$($Config.EventLogSource)" -ForegroundColor Cyan
        Write-Host "File log: $($Config.FileLogPath)" -ForegroundColor Cyan
        
        # For Wazuh integration, you might want to output the JSON
        # Write-Output ($result.Data | ConvertTo-Json -Compress)
    }
    else {
        Write-Host "Audit completed but failed to write to Event Log" -ForegroundColor Yellow
        Write-Host "Check file log at: $($Config.FileLogPath)" -ForegroundColor Cyan
    }
}
catch {
    Write-Error "Audit failed: $_"
    exit 1
}
