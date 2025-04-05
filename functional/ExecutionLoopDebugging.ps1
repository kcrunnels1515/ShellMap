# IP Subnet:
function Get-IPSubnet([IPAddress]$baseAddress, [int]$subnet, [UInt32]$pos) {
	
	# create submask by making subnet num of 1's in UInt32, and
	# convert it into a byte array
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

# Execution Loop Start:
$startTime = Get-Date -Format "yyyy-MM-dd HH:mm"
$timeZone = (Get-TimeZone).StandardName
Write-Output "Starting ShellMap at $startTime $timeZone"

$outputObjects = @() # To store all output objects

# Loops HOSTS:
$HOSTS | ForEach-Object
{
######## RESOLVE FLAG: #####################
    $resolvedIP = (Resolve-DnsName -Name $_.BASE_HOST -Type A | Select-Object -First 1).IPAddress
############################################

    # Catch in case the resolve Flag isnt used (resolvedIP never set:)
    if($resolvedIP -eq $null)
    {
        $resolvedIP = $_.BASE_HOST
    }

    # Subnet loop: (all hosts) THIS IS WHERE THE SCRIPTS WILL POPULATE!
    $maxPos = 1 -shl (32 - $_.SUBNET)
    for ( $i = 0; $i -lt $maxPos; $i++) 
    {
        
        $hostIP = Get-IPSubnet $resolvedIP $_.SUBNET $i

        


        $output = [PSCustomObject]@{
            HOST = $hostIP
            HOSTNAME = $hostName
    
            HOSTSTATUS = $hostStatus # the name of this column will never be used (Host ---- is "up/down" is the message)
            LATENCY = $latency
    
            PORT = $port
            STATUS = $portStatus
            SERVICE = $service
        }
    }
}

