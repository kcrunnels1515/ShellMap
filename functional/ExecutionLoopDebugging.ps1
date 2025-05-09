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

# Execution Loop Start:
$startTime = Get-Date -Format "yyyy-MM-dd HH:mm"
$timeZone = (Get-TimeZone).StandardName
Write-Output "Starting ShellMap at $startTime $timeZone"

$outputObjects = @() # To store all output objects
$ADDN_SCANS = addn_scans()
if (Test-Path function:global:top_ports) {
    $PORTS = top_ports()
}
if (Test-Path function:global:excluded_ports) {
    $PORTS = excluded_ports()
}
if (Test-Path function:global:limit_ports) {
    $PORTS = limit_ports()
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
    else if (-not $_.RESOLV ) {
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
            foreach $addn_scan in $ADDN_SCANS {
                $output.SCAN_RES += &$addn_scan.FN $hostIP $addn_scan.VAL
            }
        }
        # i guess print output?
    }
}
