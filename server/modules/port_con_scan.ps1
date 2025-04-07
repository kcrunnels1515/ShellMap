#Write-Host port_con_scan.ps1
# -sT
# Requires input of ports ($PORTS) and ipAddress ($hostIP)

#Write-Host port_ack_scan.ps1 "This feature has not been added."
# -sA
# This feature is currently not reachable due to blockers of PowerShell.

function port_con_scan() {
    param(
        [IPAddress]$hostIP,
        [PSCustomObject[]]$ports
    )
    $jobs = @() # Job array to hold all jobs (parallel threads)

    # Port scanning script block (for usage in the jobs!!)
    $scan_w_con = {
        param(
            [IPAddress]$hostIP,
            [int]$port
        )

        $status = $false # Port starts at closed

        # Deciding service value based off top 10+ ports and scan practices:
        # Reference: https://nmap.org/book/port-scanning.html#most-popular-ports
        $service = if ($SERVICES[$port]) {
            $SERVICES[$port]
        } else {
            "unknown service"
        }

        # TCP does a 3-way handshake: client -> SYN to server. server -> SYN + ACK to client. client -> ACK to server
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        # Try-catch block for determining the port status:
        try
        {
            $tcpClient.Connect($hostIP, $port) # Try to connect to the TCP Client
            # Success: actively listening for connections: OPEN
            $status = "OPEN"
        }
        catch # If an exception occurs
        {
            # Active rejection or no listener = CLOSED & timeout = FILTERED: so check for blocked exception message
            if ($_.Exception.Message -match "actively refused")
            {
                $status = "CLOSED"
            }
            else # Cannot be determined (either timeout or failed to respond after sending: FILTERED)
            {
                $status = "FILTERED"
            }
        }
        # Close TCP Client!
        $tcpClient.Close()

        # Return the results of the port (PORT STATUS SERVICE)
        return [PSCustomObject]@{
            PORT = $port
            PORTSTATUS = $status
            SERVICE = $service
        }
    }
    $con_scan_scr = {
        param(
            [IPAddress]$hostAddr,
            [PSCustomObject]$portval
        )
        port_range($portval,$hostAddr,$scan_w_con)
    }

    # Connect to the server using the IP address and specified port
    foreach($port in $ports)
    {
        # Start the job using the portScriptBlock:
        $jobs += Start-Job -ScriptBlock $con_scan_scr -ArgumentList $hostIP, $port
    }
    # First wait on each job before collecting the info (this means the slowest job will delay output slightly):
    Wait-Job -Job $jobs | Out-Null # Mute the actual thread info here!

    # Receive for each job: and then reformat the output
    $outputs = @()
    foreach($job in $jobs)
    {
        $output = Receive-Job -Job $job
        $outputs += $output
    }

    # return the scan objects
    $outputs
}

