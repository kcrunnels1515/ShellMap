function Parse-Ip-Subnet([IPAddress]$base_addr, [int]$subnet, [UInt32]$pos) {
	
	# create submask by making subnet num of 1's in UInt32, and
	# convert it into a byte array
	$submask = [System.BitConverter]::GetBytes([UInt32]::MaxValue -shl (32 - $subnet))
	
	# convert position (identifier of single host) to bytes to 
	# add into final result
	$id = [System.BitConverter]::GetBytes($pos)
	
	# collector byte array to store correct order of bytes for address
	$col = [byte[]]@(0,0,0,0)
	
	# ip address byte array is big-endian, reverse to apply submask
	$ip_bytes = @([System.Collections.Stack]::new(@([Byte[]]$base_addr.GetAddressBytes())))
	
	# calculate last index so we don't have to access it every time
	$last_ind = $ip_bytes.Length - 1
	
	for ( $i = 0; $i -le $last_ind; $i++) {
		# clear bits of base address that will be varied in subnet
		$ip_bytes[$i] = $ip_bytes[$i] -band $submask[$i]
		# add bits from id to cleared ip bits
		$ip_bytes[$i] = $ip_bytes[$i] -bor $id[$i]
		# place calculated byte into correct location in collector
		$col[$last_ind - $i] = $ip_bytes[$i]
	}
	# convert final collected value into uint32, and the into an ip address
	[IPAddress][System.BitConverter]::ToUInt32($col, 0)
}

function Print-IP-Subnet([string]$addr, [int]$subn) {
	$max_pos = 1 -shl (32 - $subn)
	$ip_obj = [IPAddress]$addr
	for ( $i = 0; $i -lt $max_pos; $i++) {
		$res = Parse-Ip-Subnet $ip_obj $subn $i
		echo $res.ToString()
	}
}