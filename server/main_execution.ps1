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
        [string]$scrb_str
    )
    $port_scan = [ScriptBlock]::Create($scrb_str)
    $output = @()
    for ($i = 0; $i -lt $port.RANGE; $i++) {
        $output += (&$port_scan $hostIP ($port.PORT + $i))
    }
    return $output
}

function Write-HostOutput() {
    param(
        [PSCustomObject[]]$scan_results
    )
    foreach ($scan_res in $scan_results) {
        $hostIP = $scan_res.HOST

        if (-not $scan_res.HOST) {
            $hostIP = "?.?.?.?"
        }
        Write-Host "Shellmap scan report for $($scan_res.HOSTNAME) ($($hostIP))"
        if ($scan_res.HOSTSTATUS -gt 0) {
            Write-Host "Host is up ($($scan_res.LATENCY) latency)"
        } elseif ($scan_res.HOSTSTATUS -lt 0) {
            Write-Host "Host seems down."
            continue
        } else {
            Write-Host "No information on host"
        }
        # a link-break
        Write-Host ""
        if ($scan_res.SCAN_RES) {
            $scan_res.SCAN_RES = $scan_res.SCAN_RES | Sort-Object -Property PORT
            $scan_res.SCAN_RES | Format-Table -Property PORT, STATUS, SERVICE -AutoSize
        }
    }
}
function main_exec() {
    # Execution Loop Start:
    $startTime = Get-Date -Format "yyyy-MM-dd HH:mm"
    $timeZone = (Get-TimeZone).StandardName
    Write-Host "Starting ShellMap at $startTime $timeZone"

    if (Test-Path function:global:addn_scans){
        $ADDN_SCANS = addn_scans
    }
    if (Test-Path function:global:top_ports) {
        $PORTS = top_ports
    }

    if ($EXCL_PORTS) {
       $PORTS = excluded_ports
    }

    if ($LIMIT_PORTS) {
        $PORTS = limit_ports
    }
    if ($RAND_PORTS) {
       $PORTS = randomize_ports
    }

    # for counting scanned hosts
    $hostsUp = 0
    $totalHosts = 0


    # Timer:
    $stopWatch = New-Object System.Diagnostics.Stopwatch
    $stopWatch.Start();

    # Normally this comes after resolution, but you can't loop an empty array.
    if($HOSTS.Length -eq 0)
    {
        Write-Host "WARNING: No targets were specified, so 0 hosts scanned."
    }

    # Loops HOSTS:
    foreach($hostin in $HOSTS)
    {
        # write-host "entered loop"
        ######## RESOLVE FLAG: #####################
        ########
        #### Resolving should only run when it is possible
        #$resolvedIP = (Resolve-DnsName -Name $_.BASE_HOST -Type A | Select-Object -First 1).IPAddress
        ############################################
        if ($CAN_RESOLV -and $hostin.RESOLV) {
            # write-host "resolving name"
            $hostin.ADDR = resolve($hostin)
        }
        elseif (-not $hostin.RESOLV ) {
            #write-host "not resolving"
            $hostin.ADDR = [IPAddress]($hostin.BASE_HOST)
        }

        # Catch in case the resolve Flag isnt used (resolvedIP never set:)
        # $null by default, don't need to set this if IP is not resolved/calculated
        #if($resolvedIP -eq $null)
        #{
        #    $resolvedIP = $hostin.BASE_HOST
        #}

        $outputObjects = @() # To store all output objects

        # Subnet loop: (all hosts) THIS IS WHERE THE SCRIPTS WILL POPULATE!
        $maxPos = 1 -shl (32 - $hostin.SUBN)
        for ( $i = 0; $i -lt $maxPos; $i++)
        {
            $totalHosts++
            #write-host "entered subnet loop"
            $hostIP = Get-IPSubnet $hostin.ADDR $hostin.SUBN $i
            if ($null -eq $hostIP) {
                # Cannot resolve IP/improper IP:
                Write-Host "Failed to resolve $($hostin.ADDR)"
            }
            $output = [PSCustomObject]@{
                HOST = $hostIP
                HOSTNAME = if ($hostin.RESOLV) {$hostin.BASE_HOST} else { $hostIP }

                HOSTSTATUS = 0 # the name of this column will never be used (Host ---- is "up/down" is the message)
                LATENCY = $null

                SCAN_RES = @()
            }

            if ($hostIP -eq $null) {
                #write-host "did not get an ip to scan"
                # can't do anything, say something in output to this effect
            } else {
                # discover hosts, if we can
                # dose nothing if we can't
                #write-host "Run host discovery"
                if ($HOST_DISC) {
                    host_disc($output)
                }
                if ($output.HOSTSTATUS -gt 0) {
                    $hostsUp++
                }
                # get the results for running the actual scan
                # if this is a ping/list scan, shouldn't do anything
                #write-host "running scan on host"
                $output.SCAN_RES += default_scan($hostIP)
                # if more scan have been specified on particular ports, add them
                # to the scan results list
                foreach ($addn_scan in $ADDN_SCANS) {
                    #write-host "running some additional scans"
                    $output.SCAN_RES += (&$addn_scan.FN $hostIP $addn_scan.VAL)
                }
            }
            #write-host "adding output to list of objects"
            #write-host "output object: $output"
            $outputObjects += $output
        }
        Write-HostOutput($outputObjects) | Out-Host
    }
    $elapsedTime = $stopWatch.Elapsed.TotalMilliseconds
    Write-Host "Shellmap done: $($totalHosts) IP addresses ($($hostsUp) hosts up) scanned in $($elapsedTime) ms."
}
