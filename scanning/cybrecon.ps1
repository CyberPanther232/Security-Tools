#!/usr/bin/pwsh

<#
Program: cybrecon.ps1
Purpose: Multipurpose reconnaissance toolkit designed to assist with ethical hacking and penetration testing
Developer: Cybersniper-dev
Version: 0.1
Scripting Language: PowerShell
#>

function banner {

    Write-Host "  
       ___      _                              
      / __\   _| |__  _ __ ___  ___ ___  _ __  
     / / | | | | '_ \| '__/ _ \/ __/ _ \| '_ \ 
    / /__| |_| | |_) | | |  __/ (_| (_) | | | |
    \____/\__, |_.__/|_|  \___|\___\___/|_| |_|
          |___/                            
                Cyber Recon Security Toolkit PS v0.1
                Developed by -  Kinney            
        "
}
function pingsw {
    param (
        [string]$targetSubnet
    )

    if (-not $targetSubnet) {
        Write-Host "`nUsage: cybrecon.ps1 pingsw <target-subnet - CIDR notation>`n"
        Write-Host "Example: cybrecon.ps1 pingsw 192.168.1.1/25`n"
        exit 0
    }

    Write-Host "Running ping sweep on $targetSubnet!"
    Write-Host "Hosts up:"
    
    nmap -sn $targetSubnet | Where-Object { $_ -match "Nmap scan report for" } | ForEach-Object { ($_ -split '\s+')[4] }
}

# WIP
function portenum {
    param (
        [String]$target
        [int[]]$portArray = @(20,1023)
        [String]$targetFile
    )

    $portArray 

    $command = 'nmap'

    if (-not $target) {
        Write-Host "`nUsage: cybrecon.ps1 portenum <target/target-subnet> <ports> <file>`n"
        Write-Host "Example: cybrecon.ps1 portenum 192.168.1.1/25 80,1024`n"
        Write-Host "`nExample: cybrecon.ps1 portenum target-file 22,80 f`n"
        exit 0
    }

    if (-not $file) 

    for ($port = $portArray[0]; $port < $portArray[2]; $port++) {

    }

}

if (-not $args[0]) {
banner
Write-Host "Cybrecon Options"

Write-Host "    pingsw   - Ping sweep on specific subnet"
Write-Host "(WIP)    portenum - Port enumeration scan on target or subnet"
Write-Host "(WIP)    bangrab - Banner grabbing scan on target or subnet"
Write-Host "(WIP)    httpenum - Detects for HTTP server and information regarding the server"
Write-Host "(WIP)    siteenum - Runs proxychains scanning commands on website to enumerate website info"
Write-Host "(WIP)    smb-os - Utilizes smb-os-discovery on target or subnet"
Write-Host "(WIP)    net-file - Uses pingsw to develop a network file to use for other scans/tools"
Write-Host "(WIP)    socks - Detects if a SOCKS5 proxy is running on the machine and can kill it"
Write-Host "(WIP)    qscan - Runs netcat quick scan to enumerate ports and gather any FTP or HTTP pages"
Write-Host "(WIP)    subcalc - Calculates the subnetting information from a given CIDR notation"
Write-Host "(WIP)    os-dis - Operating System Discovery tool that will attempt to discover the target(s) OS"
Write-Host "(WIP)    fuzzy - Simple fuzzer that can utilize custom or default fuzzlist"
Write-Host "(WIP)    web-shot - Fires all web-based tools in the cybrecon toolkit at a target or targets and saves it to a file"
Write-Host ""
}


if ($args[0] -eq 'pingsw' -and $args.Count -gt 1) {
    pingsw $args[1]
} elseif ($args[0] -eq 'portenum') {
    portenum
}