Import-Module $PSScriptRoot\SubNet-Calculate.psm1

# Concept: 
# Perform host discovery, only try and connect to active hosts from the ip list.
# Open = application is responding to TCP (or UDP) ** Primary goal of port scanning
# Closed = application is responding to TCP (or UDP) BUT, it is not listening (no service active)
# Filtered = No response from ACK, (timeout).
# Unfiltered = Not possible without admin permissions.

function Write-PortScanning([ipaddress]$resolvedIP)
{    
    Write-Output "Scanning IP $resolvedIP"

    # Only scan if the host ip is active:
    $activeHost = Get-ActiveHost $resolvedIP
    if($activeHost -eq $false)
    {
        return
    }

    # Establish variables:
    #$ports = @(22, 25, 80, 135, 139, 445) # To be updated if ports are specified! (top 5 default)
    $ports = @(21, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 3306) # To be updated if ports are specified! (top 5 default)
    $jobs = @() # Job array to hold all jobs (parallel threads)

    # Port scanning script block (for usage in the jobs!!)
    $portScriptBlock = {
        param(
            [string]$ipAddress,
            [string]$port
        )  
        
        $status = $false # Port starts at closed

        # Deciding service value based off top 10+ ports and scan practices:
        # Reference: https://nmap.org/book/port-scanning.html#most-popular-ports
        switch($port)
        {
            21 {$service = "ftp"}
            22 {$service = "ssh"}
            23 {$service = "telnet"}
            25 {$service = "smtp"}
            53 {$service = "domain"}
            80 {$service = "http"}
            110 {$service = "pop3"}
            111 {$service = "rpcbind"}
            135 {$service = "msrpc"}
            139 {$service = "netbios-ssn"}
            143 {$service = "imap"}
            443 {$service = "https"}
            445 {$service = "microsoft-ds"}
            465 {$service = "smtps"}
            587 {$service = "submission"}
            993 {$service = "imaps"}
            995 {$service = "pop3s"}
            3306 {$service = "mysql"}
            3389 {$service = "ms-team-server"}
            9929 {$service = "nping-echo"}
            31337 {$service = "Elite"}
        }
        
        # TCP does a 3-way handshake: client -> SYN to server. server -> SYN + ACK to client. client -> ACK to server
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        # Try-catch block for determining the port status: 
        try 
        {
            $tcpClient.Connect($ipAddress, $port) # Try to connect to the TCP Client 
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
        $jobs += Start-Job -ScriptBlock $portScriptBlock -ArgumentList $ipAddress, $port
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

    # Format the output to be the table of actual port statuses:
    $outputs | Format-Table -Property PORT, STATUS, SERVICE -AutoSize
    $elapsedTime = $stopWatch.Elapsed.TotalMilliseconds
    Write-Output "ShellMap scanned in $elapsedTime ms" 
}