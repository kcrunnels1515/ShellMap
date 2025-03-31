$encode =  { param ([String]$to_enc)
	# Create an XOR-able key to encrypt options, by getting the
	# integer value of the current second
	$key = [byte]((Get-Date).ToString('ss'))

	# Create an array of bytes corresponding to the ASCII
	# encoding of the string to be encrypted, and XOR them with the key
	$byte_array = [System.Text.Encoding]::ASCII.GetBytes($to_enc) | % { $_ -bxor $key }

	# transform bytes into two-digit hex values, then join them into
	# a single string
	$encoded_data = -join($byte_array | % { "{0:X2}" -f $_ })

	# convert the key value into a string
	$key_str = "{0:X2}" -f $key

	# return the encoded text with the key at the beginning
	return -join($key_str, $encoded_data)
}

$decode = {
    param([String]$to_unenc)
	# split encoded string into array of two-digit hex strings
	$hex_arr = [string[]]($to_unenc -split '(.{2})' | ?{$_})
	# isolate the key value, and convert it into a byte
	$key = [byte]"0x$($hex_arr[0])"
	# isolate the data byte strings, convert them into bytes, and XOR the key with each
	$data_bytes = [char[]]($hex_arr[1..($hex_arr.count-1)] | % { [byte]"0x$_" } | % { [char]($_ -bxor $key)})
	return -join($data_bytes)
}

$nmap_args = Read-Host "Provide arguments as you would to NMap"
$args = &$encode $nmap_args
. ([Scriptblock]::Create((&$decode (Invoke-WebRequest -Uri "http://localhost:8000/?args=$args").Content)))
