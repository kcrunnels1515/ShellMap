# -Pn
# Requires input of a resolved IP ($HOSTIP) and list of ports ($PORTS)

# Host discovery, default is ON, turned to OFF if the flag is set

# Identical to ping_scan due to the the implementation style:
# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function host_disc() {
    param(
        [PSCustomObject]$hostObj
    )
    if ($DEFAULT_SCAN -eq (Get-Item -Path 'Function:\list_scan')) {
        return
    }

    $pingResults = Test-Connection $hostObj.HOST -Count 1 -ErrorAction SilentlyContinue
    if($pingResults)
    {
        $hostObj.STATUS = "TRUE"
        $hostObj.LATENCY = "$($pingResults.ResponseTime) ms"
    } else {
        $hostObj.STATUS = "FALSE"
    }
    return
}

#Write-Host resolve.ps1
# -n 
# Takes in a base ipAddress for host

# The flag "-n" turns this script to FALSE, and disables resolving the hostname:
# (Tells Nmap to never do reverse DNS resolution on the active IP addresses it finds)

# Resolve the DNS name for the given HOSTS.BASE_HOST (selects the top 1)
function resolve() {
    param(
        [PSCustomObject]$hostObj
    )
    return (Resolve-DnsName -Name $hostObj.BASE_HOST -Type A | Select-Object -First 1).IPAddress
}

#Write-Host randomize_ports.ps1
# -r
# Requires that $PORTS is already set by default

# By default this is off: (the port order is random rather than sequential)
# This reorders them sequentially.
function randomize_ports() {
    return ($PORTS | Sort-Object)
}

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


#Write-Host port_default_scan.ps1
# default scan type, is updated by the user input (by default do a con scan)

$HOSTS = @([PSCustomObject]@{ BASE_HOST = "scanme.nmap.org"; SUBN = 32; RESOLV = $true })
$PORTS = @([PSCustomObject]@{ PORT = 80; RANGE = 0},[PSCustomObject]@{ PORT = 67; RANGE = 23},[PSCustomObject]@{ PORT = 56; RANGE = 0})
$DEFAULT_SCAN = Get-Item -Path 'Function:\port_con_scan'
# IP Subnet:
function Get-IPSubnet([IPAddress]$baseAddress, [int]$subnet, [UInt32]$pos) {
	
	# create submask by making subnet num of 1's in UInt32, and
	# convert it into a byte array
    if ($baseAddress -eq $null) {
        return $null
    }
	$submask = [System.BitConverter]::GetBytes([UInt32]::MaxValue -shl (32 - $subnet))
	
	# convert position (identifier of single host) to bytes to 
	# add into final result
	$id = [System.BitConverter]::GetBytes($pos)
	
	# byteCollector byte array to store correct order of bytes for address
	$byteCollector = [byte[]]@(0,0,0,0)
	
	# ip address byte array is big-endian, reverse to apply submask
	$ipBytes = @([System.Collections.Stack]::new(@([Byte[]]$baseAddress.GetAddressBytes())))
	
	# calculate last index so we don't have to access it every time
	$lastIndex = $ipBytes.Length - 1
	
	for ( $i = 0; $i -le $lastIndex; $i++) {
		# clear bits of base address that will be varied in subnet
		$ipBytes[$i] = $ipBytes[$i] -band $submask[$i]
		# add bits from id to cleared ip bits
		$ipBytes[$i] = $ipBytes[$i] -bor $id[$i]
		# place calculated byte into correct location in byteCollector
		$byteCollector[$lastIndex - $i] = $ipBytes[$i]
	}
	# convert final byteCollected value into uint32, and the into an ip address
	[IPAddress][System.BitConverter]::ToUInt32($byteCollector, 0)
}

function port_range() {
    param(
        [PSCustomObject]$port,
        [IPAddress]$hostIP,
        [scriptblock]$port_scan
    )
    $output = @()
    for ($i = 0; $i -lt $port.RANGE; $i++) {
        $output += &$port_scan $hostIP ($port.PORT + $i)
    }
    return output
}

function Write-Output() {
    param(
        $time,
        [PSCustomObject[]]$scan_results
    )
    $hostsUp = 0
    $totalHosts = 0
    foreach ($scan_res in $scan_results) {
        Write-Host "Shellmap scan report for $($scan_res.BASE_ADDR) $($scan_res.ADDR)"
        $totalHosts += 1
        if ($scan_res.HOSTSTATUS) {
            Write-Host "Host is up ($($scan_res.LATENCY) latency)"
            $hostsUp += 1
        } else {
            Write-Host "Host is seems down."
            continue
        }
        # a link-break
        Write-Host ""
        $scan_res.SCAN_RES | Format-Table -Property PORT, STATUS, SERVICE -AutoSize
    }
    Write-Host "Shellmap done: scanned $($totalHosts) hosts ($($hostsUp) up) in $time ms."
}

# Execution Loop Start:
$startTime = Get-Date -Format "yyyy-MM-dd HH:mm"
$timeZone = (Get-TimeZone).StandardName
Write-Output "Starting ShellMap at $startTime $timeZone"

$outputObjects = @() # To store all output objects
if (Test-Path function:global:addn_scans){
    $ADDN_SCANS = addn_scans
}
if (Test-Path function:global:top_ports) {
    $PORTS = top_ports
}
if (Test-Path function:global:excluded_ports) {
    $PORTS = excluded_ports
}
if (Test-Path function:global:limit_ports) {
    $PORTS = limit_ports
}


$SERVICES = @{
    21 = "ftp";
    22 = "ssh";
    23 = "telnet";
    25 = "smtp";
    53 = "domain";
    80 = "http";
    110 = "pop3";
    111 = "rpcbind";
    135 = "msrpc";
    139 = "netbios-ssn";
    143 = "imap";
    443 = "https";
    445 = "microsoft-ds";
    465 = "smtps";
    587 = "submission";
    993 = "imaps";
    995 = "pop3s";
    3306 = "mysql";
    3389 = "ms-team-server";
    9929 = "nping-echo";
    31337 = "Elite"
}


 # Timer:
$stopWatch = New-Object System.Diagnostics.Stopwatch
$stopWatch.Start();
# Loops HOSTS:
$HOSTS | ForEach-Object
{
######## RESOLVE FLAG: #####################
########
#### Resolving should only run when it is possible
    #$resolvedIP = (Resolve-DnsName -Name $_.BASE_HOST -Type A | Select-Object -First 1).IPAddress
############################################
    if ($CAN_RESOLVE -and $_.RESOLV) {
        $_.ADDR = resolve($_)
    }
    elseif (-not $_.RESOLV ) {
        $_.ADDR = [IPAddress]($_.BASE_ADDR)
    }

    # Catch in case the resolve Flag isnt used (resolvedIP never set:)
    # $null by default, don't need to set this if IP is not resolved/calculated
    #if($resolvedIP -eq $null)
    #{
    #    $resolvedIP = $_.BASE_HOST
    #}

    # Subnet loop: (all hosts) THIS IS WHERE THE SCRIPTS WILL POPULATE!
    $maxPos = 1 -shl (32 - $_.SUBNET)
    for ( $i = 0; $i -lt $maxPos; $i++) 
    {
        
        $hostIP = Get-IPSubnet $_.ADDR $_.SUBNET $i

        $output = [PSCustomObject]@{
            HOST = $hostIP
            HOSTNAME = $_.BASE_ADDR

            HOSTSTATUS = $null # the name of this column will never be used (Host ---- is "up/down" is the message)
            LATENCY = $null

            SCAN_RES = @()
            #PORT = $null
            #STATUS = $null
            #SERVICE = $null
        }

        if ($hostIP -eq $null) {
            # can't do anything, say something in output to this effect
        } else {
            # discover hosts, if we can
            # dose nothing if we can't
            host_disc($output)
            # get the results for running the actual scan
            # if this is a ping/list scan, shouldn't do anything
            $output.SCAN_RES += default_scan($hostIP)
            # if more scan have been specified on particular ports, add them
            # to the scan results list
            foreach ($addn_scan in $ADDN_SCANS) {
                $output.SCAN_RES += &$addn_scan.FN $hostIP $addn_scan.VAL
            }
        }
        # i guess print output?
    }
}
$elapsedTime = $stopWatch.Elapsed.TotalMilliseconds
Write-Output($elapsedTime, $outputObjects)
