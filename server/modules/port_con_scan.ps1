Write-Host port_con_scan.ps1
# -sT
# Requires input of ports ($PORTS) and ipAddress ($HOSTIP)

# Will scan all ports (top 20), on all hosts, only if it's active:

# ICMP echo request (PING): with select to only get the PingCheck, silently continue if errors (host down)
$pingResults = Test-Connection $HOSTIP -Count 1 -ErrorAction SilentlyContinue
if($pingResults) # Only scan active hosts
{
    $jobs = @() # Job array to hold all jobs (parallel threads)

    # Port scanning script block (for usage in the jobs!!)
    $portScriptBlock = {
        param(
            [string]$HOSTIP,
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
            $tcpClient.Connect($HOSTIP, $port) # Try to connect to the TCP Client 
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
    
    # Connect to the server using the IP address and specified port
    foreach($port in $PORTS)
    { 
        # Start the job using the portScriptBlock:
        $jobs += Start-Job -ScriptBlock $portScriptBlock -ArgumentList $HOSTIP, $port
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
    
    # Return the PORT, STATUS, SERVICE object
    return $outputs
} else # Otherwise the host is inactive
{ 
    Write-Output "Host is down"
}