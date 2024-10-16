<#
.SYNOPSIS
    Audits Windows services and checks if their associated executables grant 'Everyone' group Read/Write (RW) access.

.DESCRIPTION
    This script queries all services on a Windows machine using different methods (Get-Service & WMI, SC, and WMIC)
    to retrieve the path of their executable files. It then checks if the 'Everyone' group has Read/Write (RW)
    access to those executable files using `icacls`.

    The script supports multiple verbosity levels to control the output:

    - Verbosity 0 (default): Only shows services where RW access is found.
    - Verbosity 1: Shows information about every service except where the executable is not found.
    - Verbosity 2: Shows all output, including services with errors such as "Executable not found".

.PARAMETER verbosity
    Defines the level of verbosity for the output:

    - 0: Only shows services where RW access is detected (default).
    - 1: Shows all services and their associated executable paths, excluding "Executable not found" errors.
    - 2: Shows all services, including services with "Executable not found" and other errors.

    This parameter accepts integers (0, 1, or 2).

.EXAMPLE
    Check-ServicesForRWAccess -verbosity 0
    Runs the audit and only outputs information for services where the 'Everyone' group has RW access.

.EXAMPLE
    Check-ServicesForRWAccess -verbosity 1
    Runs the audit and outputs detailed information about all services except those with missing executables.

.EXAMPLE
    Check-ServicesForRWAccess -verbosity 2
    Runs the audit and outputs information about all services, including those with errors or missing executables.

.NOTES
    The script attempts multiple methods to gather service information and gracefully handles errors if one method
    fails. It uses `icacls` to check the file permissions for the executable paths associated with each service.

    The following methods are attempted:
    - Get-Service & WMI
    - SC query
    - WMIC

    The script will try the next method if the current one fails.

.AUTHOR
    Drake Axelrod
#>
function Invoke-CheckServiceHijack {
    param (
        [int]$verbosity = 0  # Default verbosity level is 0 (show only RW access)
    )

    Write-Host " _____ _               _      _____                 _            _   _ _ _            _    " -ForegroundColor Magenta
    Write-Host "/  __ \ |             | |    /  ___|               (_)          | | | (_|_)          | |   " -ForegroundColor Magenta
    Write-Host "| /  \/ |__   ___  ___| | __ \ ``--.  ___ _ ____   ___  ___ ___  | |_| |_ _  __ _  ___| | __" -ForegroundColor Magenta
    Write-Host "| |   | '_ \ / _ \/ __| |/ /  ``--. \/ _ \ '__\ \ / / |/ __/ _ \ |  _  | | |/ _`` |/ __| |/ /" -ForegroundColor Magenta
    Write-Host "| \__/\ | | |  __/ (__|   <  /\__/ /  __/ |   \ V /| | (_|  __/ | | | | | | (_| | (__|   < " -ForegroundColor Magenta
    Write-Host " \____/_| |_|\___|\___|_|\_\ \____/ \___|_|    \_/ |_|\___\___| \_| |_/_| |\__,_|\___|_|\_\" -ForegroundColor Magenta
    Write-Host "                                                                       _/ |                " -ForegroundColor Magenta
    Write-Host "                                                                      |__/ by Drake Axelrod" -ForegroundColor Magenta
    Write-Host "Verbosity Level: $verbosity" -ForegroundColor Cyan

    function Log {
        param (
            [string]$message,
            [int]$level=0,
            [string]$color="Gray"
        )
        $LogLevels = @("Info", "Warning", "Error", "Service", "Vulnerable", "Path")
        Write-Host -NoNewline "["
        Write-Host -NoNewline $LogLevels[$level] -ForegroundColor @("Green", "Yellow", "Red", "Blue", "Magenta", "Cyan")[$level]
        Write-Host -NoNewline "] "
        Write-Host "$message" -ForegroundColor $color
    }
    # Function to check RW permissions using icacls
    function Check-EveryoneRWAccess {
        param (
            [string]$filePath
        )
        try {
            $acl = icacls $filePath 2>&1
            if ($acl -match "Everyone:\(.*(R|W).*\)") {
                return $true
            } else {
                return $false
            }
        } catch {
            if ($verbosity -ge 2) {
                Log "Unable to check ACL for $filePath using icacls" 2
                # Write-Host "[Error] Unable to check ACL for $filePath using icacls" -ForegroundColor Red
            }
            return $false
        }
    }

    # Function to handle the output based on verbosity level
    function Output-Result {
        param (
            [string]$serviceName,
            [string]$exePath,
            [bool]$rwAccess
        )

        if ($rwAccess) {
            # Write-Host "[Warning] 'Everyone' group has RW access to $exePath!" -ForegroundColor Blue
            Log "'Everyone' group has RW access to $exePath" 4
        } else {
            if ($verbosity -ge 1) {
                # Write-Host "[Info] 'Everyone' group does NOT have RW access to $exePath." -ForegroundColor Green
                Log "'Everyone' group does NOT have RW access to $exePath." 0
            }
        }
    }

    # Function to handle error when an executable is not found
    function Handle-ExecutableNotFound {
        param (
            [string]$exePath
        )
        if ($verbosity -ge 2) {
            # Write-Host "Error: Executable not found at $exePath" -ForegroundColor Red
            Log "Executable not found at $exePath" 2
            # Write-Host "Possible reasons: The file path may be incorrect, the file may have been deleted, or access to the directory may be restricted." -ForegroundColor DarkYellow
            Log "Possible reasons: The file path may be incorrect, the file may have been deleted, or access to the directory may be restricted." 1
        }
    }

    # Function to get services using Get-Service and WMI, checking the executable file's ACL
    function Query-UsingGetService {
        Write-Host "`n--- Trying Get-Service and WMI Method ---" -ForegroundColor Yellow
        try {
            $services = Get-WmiObject -Class Win32_Service
            foreach ($service in $services) {
                $pathName = $service.PathName
                if ($pathName) {
                    $exePath = $pathName

                    if ($verbosity -ge 0) {
                        Write-Host ""
                        Log "$($service.DisplayName)" 3 "White"
                        Log "$exePath" 5
                    }

                    if (Test-Path $exePath) {
                        $rwAccess = Check-EveryoneRWAccess $exePath
                        Output-Result -serviceName $service.DisplayName -exePath $exePath -rwAccess $rwAccess
                    } else {
                        Handle-ExecutableNotFound -exePath $exePath
                    }
                } else {
                    if ($verbosity -ge 1) {
                        Log "No executable path found for service: $($service.DisplayName)" 1
                    }
                }
            }
        } catch {
            if ($verbosity -ge 2) {
                Log "Unable to query services using Get-Service and WMI." 2
            }
            return $false
        }
        return $true
    }

    # Function to get services using sc query method
    function Query-UsingSC {
        Write-Host "`n--- Trying sc query method ---" -ForegroundColor Yellow
        try {
            $services = sc.exe query state= all | Select-String "SERVICE_NAME" | ForEach-Object { ($_ -split ':')[1].Trim() }
            foreach ($service in $services) {
                if ($verbosity -ge 1) {
                    Write-Host ""
                    Log "$service" 3 "White"
                }
                $serviceDetail = sc.exe qc $service 2>&1
                $pathName = ($serviceDetail -match "BINARY_PATH_NAME\s*:\s*(.*)") ? $matches[1].Trim() : $null

                if ($pathName) {
                    $exePath = $pathName

                    if ($verbosity -ge 0) {
                        Log "Executable Path: $exePath" 0
                    }

                    if (Test-Path $exePath) {
                        $rwAccess = Check-EveryoneRWAccess $exePath
                        Output-Result -serviceName $service -exePath $exePath -rwAccess $rwAccess
                    } else {
                        Handle-ExecutableNotFound -exePath $exePath
                    }
                } else {
                    if ($verbosity -ge 1) {
                        Log "No executable path found for service: $service" 1
                    }
                }
            }
        } catch {
            if ($verbosity -ge 2) {
                Log "Unable to query services using sc." 2 #"Red"
            }
            return $false
        }
        return $true
    }

    # Function to get services using WMIC
    function Query-UsingWMIC {
        Write-Host "`n--- Trying WMIC method ---" -ForegroundColor Yellow
        try {
            $services = wmic service get Name,PathName | Where-Object { $_ -match '\S' }  # Ignore empty lines
            foreach ($service in $services) {
                $fields = $service -split '\s{2,}'  # Split based on two or more spaces
                $serviceName = $fields[0]
                $pathName = $fields[1]

                if ($pathName) {
                    $exePath = $pathName

                    if ($verbosity -ge 0) {
                        Write-Host ""
                        Log "$serviceName" 3 "White"
                        Log "$exePath" 5
                    }

                    if (Test-Path $exePath) {
                        $rwAccess = Check-EveryoneRWAccess $exePath
                        Output-Result -serviceName $serviceName -exePath $exePath -rwAccess $rwAccess
                    } else {
                        Handle-ExecutableNotFound -exePath $exePath
                    }
                } else {
                    if ($verbosity -ge 1) {
                        # Write-Host "No executable path found for service: $serviceName" -ForegroundColor DarkYellow
                        Log "No executable path found for service: $serviceName" 1
                    }
                }
            }
        } catch {
            if ($verbosity -ge 2) {
                Log "Unable to query services using WMIC." 2
            }
            return $false
        }
        return $true
    }

    # Main script execution
    $success = Query-UsingGetService
    if (-not $success) {
        $success = Query-UsingSC
    }
    if (-not $success) {
        $success = Query-UsingWMIC
    }

    # Write-Host "`n=== Script execution complete. ===" -ForegroundColor Cyan
}