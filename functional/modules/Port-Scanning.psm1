Import-Module $PSScriptRoot\SubNet-Calculate.psm1

# Overview/Concept: 
# FIRST: Establish what hosts are even available (host discovery) (ensure efficiency)
# Then connect to ports on those:
# Use a TCP cliet (dot net TCP) to send a handshake to a port (SYN) 
# SYN/ACK: The target responds with a SYN/ACK packet if the port is open. 
# RST: If the port is closed, the target responds with a RST packet. 
# No response: If no response is received, the port is considered filtered. 
# Basic scan (unspecified ports will scan all 65535 ports or 80, 443, 21, 22, 23) UNDECIDED
# Open = application is responding to TCP (or UDP) ** Primary goal of port scanning
# Closed = application is responding to TCP (or UDP) BUT, it is not listening (no service active)
# Filtered = No response, and 
# Unfiltered = 

function Write-PortScanning([ipaddress]$resolvedIP)
{
    $ipAddress = Get-ActiveHosts $resolvedIP
    # Establish variables:
    $ports = @(80, 23, 443, 21, 22, 25) # To be updated if ports are specified! (top 5 default)
    $jobs = @() # Job array to hold all jobs (parallel threads)

    # Port scanning script block (for usage in the jobs!!)
    $portScriptBlock = {
        param(
            [string]$ipAddress,
            [string]$port
        )  
        
        $status = $false # Port starts at closed

        # Deciding service value based off top 10 ports:
        # Reference: https://nmap.org/book/port-scanning.html#most-popular-ports
        switch($port)
        {
            80 {$service = "HTTP"}
            23 {$service = "Telnet"}
            443 {$service = "HTTPS"}
            21 {$service = "FTP"}
            22 {$service = "SSH"}
            25 {$service = "HTTP"}
            3389 {$service = "ms-team-server"}
            110 {$service = "POP3"}
            445 {$service = "Microsoft-DS"}
            139 {$service = "NetBIOS-SSN"}
        }
        
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($ipAddress, $port) # Try to connect to the TCP Client (quiet errors)
        if ($tcpClient.Connected) 
        {
            # Mark as open!
            $status = "OPEN"
            # Close TCP Client!
            $tcpClient.Close()
        } else 
        {
            # The port isn't listening, it is either filtered or closed: (continue)
            $status = "CLOSED"
        }

        # Return the results of the port (PORT STATUS SERVICE)
        return [PSCustomObject]@{
            PORT = $port
            STATUS = $status
            SERVICE = $service
        }
    }

    # Timer:
    $stopWatch = New-Object System.Diagnostics.Stopwatch
    $stopWatch.Start();
    # Connect to the server using the IP address and specified port
    foreach($port in $ports)
    { 
        # Start the job using the portScriptBlock:
        $job = Start-Job -ScriptBlock $portScriptBlock -ArgumentList $ipAddress, $port
        $jobs += $job
    }
    # First wait on each job before collecting the info (this means the slowest job will delay output slightly):
    foreach($job in $jobs)
    {
        Wait-Job -Job $job | Out-Null # Mute the actual thread info here!
    }

    # Receive for each job: and then reformat the output
    $outputs = @()
    foreach($job in $jobs) 
    {
        $output = Receive-Job -Job $job
        $outputs += $output
    }

    # Format the output to be the table of actual port statuses:
    $outputs | Format-Table -Property PORT, STATUS, SERVICE -AutoSize
    $elapsedTime = $stopWatch.Elapsed.TotalMilliseconds
    Write-Output "ShellMap scanned in $elapsedTime ms" 
}