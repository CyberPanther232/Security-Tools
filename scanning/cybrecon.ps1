# Requires -Version 5.1
<#
.SYNOPSIS
    cybrecon - Multipurpose reconnaissance toolkit.
.DESCRIPTION
    A PowerShell-based multipurpose reconnaissance toolkit designed to assist with ethical hacking and penetration testing.
.NOTES
    Author: CyberPanther232 (Original Bash Script)
    PowerShell Conversion: Gemini AI
    Version: 1.1 (PowerShell)
    Requires: nmap, wget (for FTP in qscan), and potentially nc (if Test-NetConnection is not sufficient).
#>

# --- Main Script Logic ---
param (
    [string]$Command,
    [string[]]$CommandArgs
)

function Show-Banner {
    Write-Host @"
           ___      _                              
          / __\   _| |__  _ __ ___  ___ ___  _ __  
         / / | | | | '_ \| '__/ _ \/ __/ _ \| '_ \ 
        / /__| |_| | |_) | | |  __/ (_| (_) | | | |
        \____/\__, |_.__/|_|  \___|\___\___/|_| |_|
              |___/                            
                    Cyber Recon Security Toolkit v1.1
                    Developed by - CyberPanther232  1.1 (PowerShell)
                    Converted Via: Gemini AI
                    
"@
}

# Function to calculate the number of hosts, usable IP range, and the final octets of the starting and ending hosts
function Get-SubnetInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$CIDR
    )

    try {
        $ipAddress, [int]$maskLength = $CIDR.Split('/')
        $ip = [System.Net.IPAddress]::Parse($ipAddress)

        if ($ip.AddressFamily -ne 'InterNetwork') {
            Write-Error "Only IPv4 CIDR notation is supported."
            return
        }

        $ipBytes = $ip.GetAddressBytes()
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
        $ipInt = [System.Net.IPAddress]::NetworkToHostOrder($ipInt) # Ensure correct byte order

        $hostBits = 32 - $maskLength
        if ($maskLength -eq 32) {
            $numHosts = 1
        } elseif ($maskLength -eq 31) {
            $numHosts = 2 # Special case for /31, often considered 2 usable hosts (point-to-point)
        } else {
            $numHosts = ([Math]::Pow(2, $hostBits)) - 2
        }
        if ($numHosts -lt 0) {$numHosts = 0} # Avoid negative if hostBits is 0

        # Calculate network mask integer
        $maskInt = [uint32]::MaxValue -shl $hostBits
        
        $networkAddressInt = $ipInt -band $maskInt
        $broadcastAddressInt = $networkAddressInt -bor (-bnot $maskInt)

        $networkIpBytes = [System.BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($networkAddressInt))
        $broadcastIpBytes = [System.BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($broadcastAddressInt))

        # Adjust for correct byte order for IPAddress constructor if necessary
        if ([System.BitConverter]::IsLittleEndian) {
            [System.Array]::Reverse($networkIpBytes)
            [System.Array]::Reverse($broadcastIpBytes)
        }

        $networkIp = (New-Object System.Net.IPAddress($networkIpBytes)).ToString()
        $broadcastIp = (New-Object System.Net.IPAddress($broadcastIpBytes)).ToString()
        
        $firstUsableIp = $null
        $lastUsableIp = $null
        $firstIpStr = "N/A"
        $lastIpStr = "N/A"

        if ($maskLength -lt 31) {
            $firstUsableIpInt = $networkAddressInt + 1
            $lastUsableIpInt = $broadcastAddressInt - 1

            $firstUsableIpBytes = [System.BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($firstUsableIpInt))
            $lastUsableIpBytes = [System.BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($lastUsableIpInt))
            if ([System.BitConverter]::IsLittleEndian) {
                [System.Array]::Reverse($firstUsableIpBytes)
                [System.Array]::Reverse($lastUsableIpBytes)
            }
            $firstIpStr = (New-Object System.Net.IPAddress($firstUsableIpBytes)).ToString()
            $lastIpStr = (New-Object System.Net.IPAddress($lastUsableIpBytes)).ToString()
        } elseif ($maskLength -eq 31) {
            $firstIpStr = $networkIp
            $lastIpStr = $broadcastIp
        } elseif ($maskLength -eq 32) {
            $firstIpStr = $ipAddress
            $lastIpStr = $ipAddress
        }


        Write-Host "CIDR: $CIDR"
        Write-Host "Number of usable hosts: $numHosts"
        Write-Host "Usable IP range: $firstIpStr - $lastIpStr"
        Write-Host "Network address: $networkIp"
        Write-Host "Broadcast address: $broadcastIp"

        # For qscan compatibility, return specific values
        return [PSCustomObject]@{
            CIDR = $CIDR
            NumHosts = $numHosts
            FirstUsableIP = $firstIpStr
            LastUsableIP = $lastIpStr
            NetworkIP = $networkIp
            BroadcastIP = $broadcastIp
            FirstThreeOctets = $ipAddress.Substring(0, $ipAddress.LastIndexOf('.'))
            StartOctet = if ($maskLength -eq 32) { $ipAddress.Split('.')[-1] } else { $firstIpStr.Split('.')[-1] }
            EndOctet = if ($maskLength -eq 32) { $ipAddress.Split('.')[-1] } else { $lastIpStr.Split('.')[-1] }
        }

    } catch {
        Write-Error "Error calculating subnet: $($_.Exception.Message)"
    }
}

function Start-QScan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$CIDR,
        [Parameter(Position=1)]
        [string]$Ports, # Space or comma separated
        [Parameter(Position=2)]
        [switch]$VerboseScan
    )

    if (-not $CIDR) {
        Write-Host ""
        Write-Host "Usage: Start-QScan <CIDR> [-Ports <ports>] [-VerboseScan]"
        Write-Host "Example: Start-QScan 192.168.1.1/24 -Ports '21-23,80,443'"
        Write-Host ""
        return
    }

    $subnetInfo = $null
    $firstThreeOctets = ""
    $startOctet = 0
    $endOctet = 0
    $numHosts = 0

    if ($CIDR.EndsWith("/32")) {
        $ip = $CIDR.Split('/')[0]
        $firstThreeOctets = $ip.Substring(0, $ip.LastIndexOf('.'))
        $lastOctetVal = [int]$ip.Split('.')[-1]
        $startOctet = $lastOctetVal
        $endOctet = $lastOctetVal
        $numHosts = 1
        Write-Host "CIDR: $CIDR"
        Write-Host "Number of usable hosts: $numHosts"
        Write-Host "Usable IP range: $ip - $ip"
        Write-Host "Network address: $ip"
        Write-Host "Broadcast address: $ip"
    } else {
        $subnetInfo = Get-SubnetInfo -CIDR $CIDR
        if (-not $subnetInfo) { return } # Error handled in Get-SubnetInfo
        $firstThreeOctets = $subnetInfo.FirstThreeOctets
        $startOctet = [int]$subnetInfo.StartOctet
        $endOctet = [int]$subnetInfo.EndOctet
        $numHosts = $subnetInfo.NumHosts
    }

    Write-Host "Running scan on hosts!"

    if ($VerboseScan) {
        Write-Host "Running in verbose mode!"
    } else {
        Write-Host "Running in standard mode!"
    }

    if (-not $Ports) {
        Write-Host "Ports missing... Adding default (21-23 80)!"
        $Ports = "21-23 80"
    }
    
    # Convert port string to an array of individual ports and ranges
    $portArray = @()
    $Ports.Split([char[]]@(',', ' '), [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object {
        if ($_ -match "-") {
            $range = $_.Split('-')
            if ($range.Count -eq 2 -and [int]::TryParse($range[0], [ref]$null) -and [int]::TryParse($range[1], [ref]$null) ) {
                 $portArray += $_ # Keep ranges as strings for Test-NetConnection
            } else {
                Write-Warning "Invalid port range: $_"
            }
        } elseif ([int]::TryParse($_, [ref]$null)) {
            $portArray += [int]$_
        } else {
            Write-Warning "Invalid port: $_"
        }
    }
    if ($portArray.Count -eq 0) {
        Write-Error "No valid ports specified."
        return
    }


    if ($numHosts -gt 32) {
        Write-Host "Scanning $numHosts hosts!"
        Write-Host "This may take a while..."
    } else {
        Write-Host "Scanning $numHosts hosts!"
    }

    Write-Host "IP Addr - PortNum:(Protocol) = Status"

    # PowerShell jobs for parallelism
    $jobs = @()

    for ($i = $startOctet; $i -le $endOctet; $i++) {
        $currentTargetIp = "$firstThreeOctets.$i"
        
        # Process ports in chunks or one by one if using Test-NetConnection effectively
        foreach ($portEntry in $portArray) {
            $job = Start-Job -ScriptBlock {
                param($ip, $portItem, $isVerbose)

                $results = @()
                $portsToScan = @()

                if ($portItem -is [string] -and $portItem -match "-") {
                    $startP, $endP = $portItem.Split('-') | ForEach-Object { [int]$_ }
                    for ($p = $startP; $p -le $endP; $p++) {
                        $portsToScan += $p
                    }
                } else {
                    $portsToScan += [int]$portItem
                }

                foreach ($p in $portsToScan) {
                    $connectionTest = Test-NetConnection -ComputerName $ip -Port $p -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -InformationLevel Quiet
                    if ($connectionTest -and $connectionTest.TcpTestSucceeded) {
                        $protocol = (Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess # This is not reliable for remote protocol
                        # Simplified output, actual protocol detection is harder without deeper inspection
                        $serviceName = switch($p) {
                            21 {"ftp"}
                            22 {"ssh"}
                            23 {"telnet"}
                            80 {"http"}
                            443 {"https"}
                            default {"unknown"}
                        }
                        $resultLine = "$ip - $p ($serviceName) = Open"
                        $results += $resultLine
                        
                        # wget/Invoke-WebRequest logic
                        if ($p -eq 21) { # FTP
                            if ($isVerbose) { Write-Host "FTP detected on $ip. Running wget -r..." }
                            try {
                                # Assuming wget.exe is in PATH. This is a direct call.
                                # For a pure PowerShell solution, FTP recursion is more complex.
                                & wget.exe -r -q "ftp://$ip" -o "$($env:TEMP)\wget_ftp_$($ip.Replace('.','_')).log"
                                if ($LASTEXITCODE -ne 0) { Write-Warning "wget FTP for $ip returned non-zero exit code."}
                            } catch {
                                Write-Warning "Failed to run wget for FTP on ${ip}: $($_.Exception.Message)"
                            }
                        } elseif ($p -eq 80 -or $p -eq 443 -or $p -eq 8080) { # HTTP/S
                             $protocolHttp = if ($p -eq 443 -or $p -eq 8443) {"https"} else {"http"}
                            if ($isVerbose) { Write-Host "$($protocolHttp.ToUpper()) detected on $ip. Running Invoke-WebRequest -Uri ${protocolHttp}://${ip} ..." }
                            try {
                                # Invoke-WebRequest doesn't have a simple recursive download like wget -r.
                                # This will just get the front page. For full mirroring, a more complex script or wget is needed.
                                Invoke-WebRequest -Uri "${protocolHttp}://${ip}" -OutFile "$($env:TEMP)\web_content_$($ip.Replace('.','_')).html" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                if ($LASTEXITCODE -ne 0) { Write-Warning "Invoke-WebRequest for ${protocolHttp}://${ip} returned non-zero status."}
                            } catch {
                                Write-Warning "Failed to run Invoke-WebRequest for ${protocolHttp}://${ip}: $($_.Exception.Message)"
                            }
                        }
                    }#else {
                        # $results += "$ip - $p (tcp) = Closed/Filtered" # Optional: report closed
                    #}
                }
                return $results
            } -ArgumentList $currentTargetIp, $portEntry, $VerboseScan
            $jobs += $job
        }
    }

    # Wait for all jobs and collect results
    foreach ($job in $jobs) {
        Receive-Job $job | ForEach-Object { Write-Host $_ }
        Remove-Job $job # Clean up
    }
    Wait-Job -Job $jobs -ErrorAction SilentlyContinue | Out-Null # Ensure all are done
    Remove-Job -Job $jobs -ErrorAction SilentlyContinue # Final cleanup
    Write-Host "Scan complete."
}

function Manage-SocksProxy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateSet("k", "s")] # k for kill, s for status
        [string]$Action
    )

    # Find processes listening on port 9050 (common for Tor SOCKS proxy)
    try {
        $connections = Get-NetTCPConnection -LocalPort 9050 -State Listen -ErrorAction SilentlyContinue
        $pids = ($connections | Select-Object -ExpandProperty OwningProcess -Unique)
        
        if ($Action -eq "s") { # Status
            if ($pids.Count -gt 0) {
                Write-Host "Dynamic tunnel (PID(s): $($pids -join ', ')) likely exists on port 9050."
                # Get-Process -Id $pids | Select-Object Id, ProcessName, Path # More details
            } else {
                Write-Host "No dynamic tunnel detected listening on port 9050."
            }
        } elseif ($Action -eq "k") { # Kill
            if ($pids.Count -gt 0) {
                Write-Host "Attempting to kill dynamic tunnel process(es) on port 9050 (PID(s): $($pids -join ', '))..."
                Stop-Process -Id $pids -Force -ErrorAction SilentlyContinue
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Process(es) likely terminated."
                } else {
                    Write-Warning "Could not terminate all processes or an error occurred."
                }
            } else {
                Write-Host "No dynamic tunnel process found listening on port 9050 to kill."
            }
        }
    } catch {
        Write-Error "Error managing SOCKS proxy: $($_.Exception.Message)"
    }
}

function Start-PortEnumeration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        [Parameter(Position=1)]
        [string]$Ports = '20-1024', # Default ports
        [Parameter(Position=2)]
        [ValidateSet("target", "file")]
        [string]$InputType = "target" # Default to single target
    )

    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }

    $nmapCmd = "nmap"
    $nmapArgs = @()

    if ($InputType -eq "file") {
        if (-not (Test-Path -Path $Target -PathType Leaf)) { Write-Error "Target file '$Target' not found."; return }
        Write-Host "Running port enumeration using target file: $Target"
        $nmapArgs += "-iL", $Target
    } else {
        Write-Host "Running port enumeration on $Target"
        $nmapArgs += $Target
    }
    $nmapArgs += "-p$Ports"

    Write-Host "Executing: $nmapCmd $($nmapArgs -join ' ')"
    $nmapOutput = try { & $nmapCmd $nmapArgs 2>&1 } catch { Write-Warning "Nmap execution failed: $($_.Exception.Message)"; return }
    
    $currentHost = ""
    $headerPrinted = $false
    $nmapOutput | ForEach-Object {
        if ($_ -match "Nmap scan report for\s+(.*)") {
            if ($currentHost) { Write-Host "" } # Newline before new host
            $currentHost = $matches[1].Trim()
            Write-Host "Host: $currentHost"
            $headerPrinted = $false
        } elseif ($_ -match "^\d+\/(tcp|udp)\s+(open|open\|filtered|filtered|closed)\s+(.*)") {
            if (-not $headerPrinted) {
                Write-Host "Open Ports:"
                $headerPrinted = $true
            }
            if ($matches[2] -eq "open" -or $matches[2] -eq "open|filtered") { # Only show open or potentially open
                $portProto = $matches[1]
                $status = $matches[2]
                $service = $matches[3].Trim()
                Write-Host "$($_.Split('/')[0])/$portProto - $status - $service"
            }
        }
    }
}

function Start-PingSweep {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$SubnetCIDR # e.g., 192.168.1.0/24
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }

    if (-not $SubnetCIDR) {
        Write-Host ""
        Write-Host "Usage: Start-PingSweep <target-subnet - CIDR notation>"
        Write-Host "Example: Start-PingSweep 192.168.1.0/24"
        Write-Host ""
        return
    }

    Write-Host "Running ping sweep on $SubnetCIDR"
    Write-Host "Hosts up:"
    try {
        $nmapOutput = nmap -sn $SubnetCIDR # -sn: Ping Scan - disable port scan
        $nmapOutput | Select-String -Pattern "Nmap scan report for (.*)" | ForEach-Object {
            $_.Matches[0].Groups[1].Value
        }
    } catch {
        Write-Error "Error during nmap ping sweep: $($_.Exception.Message)"
    }
}

function Start-BannerGrabbing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        [Parameter(Position=1)]
        [string]$Ports = '20-1024',
        [Parameter(Position=2)]
        [ValidateSet("target", "file")]
        [string]$InputType = "target"
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }

    $nmapCmd = "nmap"
    $nmapArgs = @()

    if ($InputType -eq "file") {
        if (-not (Test-Path -Path $Target -PathType Leaf)) { Write-Error "Target file '$Target' not found."; return }
        Write-Host "Running banner grabbing using target file: $Target"
        $nmapArgs += "-iL", $Target
    } else {
        Write-Host "Running banner grabbing on target: $Target"
        $nmapArgs += $Target
    }
    $nmapArgs += "-p$Ports", "--script", "banner" # Nmap uses --script banner, not banner.nse directly in basic calls usually

    Write-Host "Executing: $nmapCmd $($nmapArgs -join ' ')"
    $nmapOutput = try { & $nmapCmd $nmapArgs 2>&1 } catch { Write-Warning "Nmap execution failed: $($_.Exception.Message)"; return }

    $currentHost = ""
    $currentPort = ""
    $nmapOutput | ForEach-Object {
        if ($_ -match "Nmap scan report for\s+(.*)") {
            if ($currentHost) { Write-Host "" }
            $currentHost = $matches[1].Trim()
            Write-Host "Host: $currentHost"
            Write-Host "Banners:"
        } elseif ($_ -match "^(\d+\/(?:tcp|udp))\s+open") {
            $currentPort = $matches[1]
        } elseif ($_ -match "\|\s*banner:\s*(.*)") { # Adjusted for typical banner script output
            $bannerText = $matches[1].Trim()
            Write-Host "$currentPort - $bannerText"
        } elseif ($_ -match "\|_(.*)") { # Catch-all for multi-line banners if needed
             Write-Host "  $_" # Indent continuation lines
        }
    }
}

function Start-HttpEnumeration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        [Parameter(Position=1)]
        [string]$Ports = "80,443,8080,8000,8800",
        [Parameter(Position=2)]
        [ValidateSet("target", "file")]
        [string]$InputType = "target"
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }

    $nmapCmd = "nmap"
    $nmapArgs = @()

    if ($InputType -eq "file") {
        if (-not (Test-Path -Path $Target -PathType Leaf)) { Write-Error "Target file '$Target' not found."; return }
        Write-Host "Running HTTP Enumeration using target file: $Target"
        $nmapArgs += "-iL", $Target
    } else {
        Write-Host "Running HTTP Enumeration on target: $Target"
        $nmapArgs += $Target
    }
    $nmapArgs += "-p$Ports", "--script", "http-enum"

    Write-Host "Executing: $nmapCmd $($nmapArgs -join ' ')"
    $nmapOutput = try { & $nmapCmd $nmapArgs 2>&1 } catch { Write-Warning "Nmap execution failed: $($_.Exception.Message)"; return }
    
    $currentHost = ""
    $pathTraversalHeaderPrinted = $false
    $nmapOutput | ForEach-Object {
        if ($_ -match "Nmap scan report for\s+(.*)") {
            if ($currentHost) { Write-Host "" }
            $currentHost = $matches[1].Trim()
            Write-Host "Host: $currentHost"
            $pathTraversalHeaderPrinted = $false
        }  elseif ($_ -match "http-enum:") { # Script output section
             # Can add more specific parsing here based on http-enum.nse output structure
            if (!$pathTraversalHeaderPrinted) {
                 # Write-Host "HTTP Enumeration Details:" # General Header
                 $pathTraversalHeaderPrinted = $true # Reset for each host
            }
        } elseif ($_ -match "(GET|POST)\s+(\S+)\s+HTTP") { # Example: Look for interesting paths found
            Write-Host "  Path found: $($matches[2])"
        } elseif ($_ -match "/\.\./") { # Basic path traversal indicator
             if (!$pathTraversalHeaderPrinted) {
                Write-Host "Possible Path Traversals/Interesting Finds:"
                $pathTraversalHeaderPrinted = $true
            }
            Write-Host "  $_"
        } elseif ($currentHost -and $_ -match "^\s+\|") { # Print lines under the current host that seem to be part of script output
            Write-Host $_
        }
    }
}

function Start-SiteEnumeration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        [Parameter(Position=1)]
        [string]$Port = "80",
        [Parameter(Position=2)]
        [ValidateSet("target", "file")]
        [string]$InputType = "target"
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }

    Write-Host "Running Website Enumeration"
    $nmapBaseCmd = "nmap -Pn -T5 -sT -p$Port" # -sT for TCP Connect scan, -Pn no ping
    $nmapArgs = @()
    $outputFile = ".\siteenum-report.txt"

    if ($InputType -eq "file") {
        if (-not (Test-Path -Path $Target -PathType Leaf)) { Write-Error "Target file '$Target' not found."; return }
        Write-Host "Running Website Enumeration using target file: $Target"
        $nmapArgs += "-iL", $Target
    } else {
        Write-Host "Running Website Enumeration on $Target"
        $nmapArgs += $Target
    }
    
    Write-Host "Executing Nmap scans... Output will be saved to $outputFile"
    
    try {
        # Using Start-Process to handle redirection better for multiple commands if needed, or just call directly
        Write-Host "Running http-enum script..."
        Invoke-Expression "$nmapBaseCmd --script http-enum $($nmapArgs -join ' ') | Out-File -FilePath $outputFile -Encoding utf8"
        
        Write-Host "Running http-sql-injection script..." # Note: http-sql-injection.nse is the correct script name
        Invoke-Expression "$nmapBaseCmd --script http-sql-injection $($nmapArgs -join ' ') | Out-File -FilePath $outputFile -Append -Encoding utf8"
        
        Write-Host "Running http-robots.txt script..."
        Invoke-Expression "$nmapBaseCmd --script http-robots.txt $($nmapArgs -join ' ') | Out-File -FilePath $outputFile -Append -Encoding utf8"

        Write-Host "Website enumeration complete!"
        Write-Host "Report written to $outputFile"
    } catch {
        Write-Error "Error during Nmap site enumeration: $($_.Exception.Message)"
    }
}

function Get-OsDiscovery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        [Parameter(Position=1)]
        [ValidateSet("target", "file")]
        [string]$InputType = "target"
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }
    # OS detection requires elevated privileges (admin/root)
    Write-Warning "OS Detection (-O) typically requires Administrator/root privileges to be effective."

    $nmapCmd = "nmap"
    $nmapArgs = @()

    if ($InputType -eq "file") {
        if (-not (Test-Path -Path $Target -PathType Leaf)) { Write-Error "Target file '$Target' not found."; return }
        Write-Host "Running OS discovery using target file: $Target"
        $nmapArgs += "-iL", $Target
    } else {
        Write-Host "Running OS discovery on target: $Target"
        $nmapArgs += $Target
    }
    $nmapArgs += "-O" # OS Detection

    Write-Host "Executing: $nmapCmd $($nmapArgs -join ' ')"
    try {
        # Nmap -O output is verbose, directly outputting it.
        & $nmapCmd $nmapArgs 2>&1 | Out-Host
    } catch {
        Write-Error "Nmap OS Discovery failed: $($_.Exception.Message)"
    }
}

function Get-SmbOsDiscovery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        [Parameter(Position=1)]
        [string]$Ports = "445", # Default SMB port
        [Parameter(Position=2)]
        [ValidateSet("target", "file")]
        [string]$InputType = "target"
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }

    $nmapCmd = "nmap"
    $nmapArgs = @()

    if ($InputType -eq "file") {
        if (-not (Test-Path -Path $Target -PathType Leaf)) { Write-Error "Target file '$Target' not found."; return }
        Write-Host "Running smb-os-discovery using target file: $Target"
        $nmapArgs += "-iL", $Target
    } else {
        Write-Host "Running smb-os-discovery on target: $Target"
        $nmapArgs += $Target
    }
    $nmapArgs += "-p$Ports", "--script", "smb-os-discovery"

    Write-Host "Executing: $nmapCmd $($nmapArgs -join ' ')"
    try {
        # Nmap script output is directly displayed
        & $nmapCmd $nmapArgs 2>&1 | Out-Host
    } catch {
        Write-Error "Nmap SMB OS Discovery failed: $($_.Exception.Message)"
    }
}

function New-NetworkFileFromPingSweep {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$SubnetCIDR
    )
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) { Write-Error "nmap is not installed or not in PATH."; return }

    if (-not $SubnetCIDR) {
        Write-Host ""
        Write-Host "Usage: New-NetworkFileFromPingSweep <subnet>"
        Write-Host "Example: New-NetworkFileFromPingSweep 192.168.1.0/24"
        Write-Host ""
        return
    }

    Write-Host "Generating network file for the $SubnetCIDR network"
    $safeSubnet = $SubnetCIDR -replace "/", "_"
    $filename = ".\${safeSubnet}_network.txt"

    try {
        $nmapOutput = nmap -sn $SubnetCIDR # -sn: Ping Scan - disable port scan
        $liveHosts = $nmapOutput | Select-String -Pattern "Nmap scan report for (.*)" | ForEach-Object {
            $_.Matches[0].Groups[1].Value
        }
        
        $liveHosts | Set-Content -Path $filename
        Write-Host "'$filename' file created with live hosts!"
    } catch {
        Write-Error "Error generating network file: $($_.Exception.Message)"
    }
}

function Start-UrlFuzzer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Url,
        [Parameter(Position=1)]
        [string]$FuzzListPath = ".\fuzzylist.txt" # Default fuzz list
    )

    if (-not (Test-Path $FuzzListPath -PathType Leaf)) {
        Write-Warning "Fuzzlist '$FuzzListPath' not found. Please create it or provide a valid path."
        # You could create a default small fuzzylist here if desired
        # @("admin", "login", "test", "backup", "config", ".git", "robots.txt") | Out-File $FuzzListPath
        return
    }

    Write-Host "Running fuzzer on $Url with fuzzlist: $FuzzListPath"
    if ($Url[-1] -ne '/') { $Url += "/" } # Ensure URL ends with a slash

    Get-Content $FuzzListPath | ForEach-Object {
        $lineToTry = $_.Trim()
        if (-not $lineToTry) { return } # Skip empty lines

        $fullUrl = "$Url$lineToTry"
        try {
            # -UseBasicParsing might be needed for some environments, but full parsing gets status code.
            $response = Invoke-WebRequest -Uri $fullUrl -Method Head -ErrorAction SilentlyContinue -TimeoutSec 5 
            if ($response) {
                Write-Host "Response: $($response.StatusCode) | $lineToTry"
            } else {
                # Could be a timeout or other error not yielding a status code object
                # Try a GET request to see if it yields more info, but HEAD is faster
                $getError = $Error[0]
                if ($getError -and $getError.Exception -is [System.Net.WebException] -and $getError.Exception.Response) {
                     $statusCode = [int]$getError.Exception.Response.StatusCode
                     Write-Host "Response: $statusCode | $lineToTry (from error)"
                } else {
                    Write-Host "Err (No response or timeout) | $lineToTry"
                }
            }
        } catch {
            $ex = $_.Exception
            if ($ex -is [System.Net.WebException] -and $ex.Response) {
                $statusCode = [int]$ex.Response.StatusCode
                Write-Host "Response: $statusCode | $lineToTry (from catch)"
            } else {
                Write-Host "Err ($($ex.GetType().Name)) | $lineToTry"
            }
        }
        $Error.Clear() # Clear error array for next request
    }
}

function Start-WebShot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Target,
        # Add -InputType (target/file) and other relevant params if this function gets implemented
        [Parameter(Position=1)]
        [ValidateSet("target", "file")]
        [string]$InputType = "target"
    )

    Write-Host "Web-Shot function (PowerShell version) is not fully implemented yet."
    Write-Host "It would call other web-focused functions like:"
    Write-Host "  Start-HttpEnumeration"
    Write-Host "  Start-SiteEnumeration"
    Write-Host "  Start-UrlFuzzer (if applicable for general directory fuzzing)"
    Write-Host "  Potentially banner grabbing on web ports."
    Write-Host "Usage: Start-WebShot <target_or_file> [-InputType <file|target>]"

    # Example of how it might be structured:
    # if ($InputType -eq "file") {
    #     Get-Content $Target | ForEach-Object {
    #         $currentTarget = $_
    #         Write-Host "--- Processing $currentTarget for WebShot ---"
    #         Start-HttpEnumeration -Target $currentTarget # -Ports "80,443,..."
    #         Start-SiteEnumeration -Target $currentTarget # -Port "80,443"
    #         # Add more calls, perhaps with output aggregation
    #     }
    # } else {
    #     Write-Host "--- Processing $Target for WebShot ---"
    #     Start-HttpEnumeration -Target $Target
    #     Start-SiteEnumeration -Target $Target
    # }
    # Write-Host "WebShot analysis would be aggregated into a report."
}

if (-not $Command) {
    Show-Banner
    Write-Host "Cybrecon Options (PowerShell Version)"
    Write-Host ""
    Write-Host "  Start-PingSweep           - Ping sweep on specific subnet (e.g., Start-PingSweep 192.168.1.0/24)"
    Write-Host "  Start-PortEnumeration     - Port enumeration on target or file (e.g., Start-PortEnumeration host.com '80,443' or targets.txt default_ports file)"
    Write-Host "  Start-BannerGrabbing      - Banner grabbing on target or file (e.g., Start-BannerGrabbing host.com '21,22,80' or targets.txt default_ports file)"
    Write-Host "  Start-HttpEnumeration     - HTTP server enumeration (e.g., Start-HttpEnumeration host.com '80,443,8080' or targets.txt default_ports file)"
    Write-Host "  Start-SiteEnumeration     - Website enumeration scripts (e.g., Start-SiteEnumeration host.com 80 or targets.txt 80 file)"
    Write-Host "  Get-SmbOsDiscovery        - SMB OS discovery (e.g., Get-SmbOsDiscovery host.com 445 or targets.txt 445 file)"
    Write-Host "  New-NetworkFileFromSweep  - Create a network file from ping sweep (e.g., New-NetworkFileFromSweep 192.168.1.0/24)"
    Write-Host "  Manage-SocksProxy         - Detect or kill SOCKS proxy (e.g., Manage-SocksProxy s OR Manage-SocksProxy k)"
    Write-Host "  Start-QScan               - Quick port scan with service interaction (e.g., Start-QScan 192.168.1.10/32 '21,80' -VerboseScan)"
    Write-Host "  Get-SubnetInfo            - Calculate subnet info from CIDR (e.g., Get-SubnetInfo 192.168.1.0/24)"
    Write-Host "  Get-OsDiscovery           - Nmap OS Discovery (e.g., Get-OsDiscovery host.com or targets.txt file)"
    Write-Host "  Start-UrlFuzzer           - Simple URL fuzzer (e.g., Start-UrlFuzzer http://host.com/FUZZ fuzzlist.txt)"
    Write-Host "  Start-WebShot             - (Placeholder) Fires all web-based tools at target(s)."
    Write-Host ""
    exit 0
}

# Construct the arguments string for functions that take variable args or rely on nmap style
$fullArgs = if ($CommandArgs) { $CommandArgs -join ' ' } else { '' }

# PowerShell uses Verbose-Noun for function names by convention
switch ($Command.ToLower()) {
    "pingsw"                 { Start-PingSweep $CommandArgs[0] }
    "portenum"               { Start-PortEnumeration $CommandArgs[0] $CommandArgs[1] $CommandArgs[2] }
    "bangrab"                { Start-BannerGrabbing $CommandArgs[0] $CommandArgs[1] $CommandArgs[2] }
    "httpenum"               { Start-HttpEnumeration $CommandArgs[0] $CommandArgs[1] $CommandArgs[2] }
    "siteenum"               { Start-SiteEnumeration $CommandArgs[0] $CommandArgs[1] $CommandArgs[2] }
    "smb-os"                 { Get-SmbOsDiscovery $CommandArgs[0] $CommandArgs[1] $CommandArgs[2] }
    "net-file"               { New-NetworkFileFromPingSweep $CommandArgs[0] }
    "socks"                  { Manage-SocksProxy $CommandArgs[0] }
    "qscan"                  { 
                                $portsArg = if ($CommandArgs.Count -gt 1) { $CommandArgs[1] } else { $null }
                                $verboseSwitch = ($CommandArgs.Count -gt 2 -and ($CommandArgs[2] -eq "-v" -or $CommandArgs[2] -eq "--verbose"))
                                Start-QScan $CommandArgs[0] $portsArg -VerboseScan:$verboseSwitch 
                             }
    "subcalc"                { Get-SubnetInfo $CommandArgs[0] }
    "os-dis"                 { Get-OsDiscovery $CommandArgs[0] $CommandArgs[1] }
    "fuzzy"                  { Start-UrlFuzzer $CommandArgs[0] $CommandArgs[1] }
    "web-shot"               { Start-WebShot $CommandArgs[0] $CommandArgs[1] } # Add more params as needed
    default {
        Write-Error "Unknown command: $Command"
        Show-Banner # Show help on unknown command
    }
}