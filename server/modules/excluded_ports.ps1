#Write-Host excluded_ports.ps1
# -exclude-ports
# Require input of exclude port list ($EXCL_PORTS)
# (default port list has already been defined at this point)
# type:
#   0 -> no overlap
#   5 -> overlap between end of port and begin of excl
#   6 -> overlap between begin of port and end of excl
#   7 -> excl overlap the middle of port
#   4 -> excl completely overlap port
#
# Removes any matches to ports from EXCL_PORTS from default PORTS and updates the variable
function excluded_ports() {
    $overlap = {
        param([int[]]$excls,[PSCustomObject]$port)
        $i = 0
        $mode = 1
        $ports = @()
        for (; $i -le $port.RANGE; $i++) {
            if ($mode) {
                if ($port.PORT + $i -in $excls) {

                }
            } else {
                if (-not $port.PORT + $i -in $excls) {
                    break;
                }
            }

        }
    }
    $my_excl = @()
    foreach ($exclObj in $EXCL_PORTS) {
        for ($i = 0; $i -le $exclObj.RANGE; $i++) {
            $my_excl += $exclObj.PORT + $i
        }
    }
    $my_ports = @()
    foreach ($portObj in $PORTS) {
        for ($i = 0; $i -le $portObj.RANGE; $i++) {
            if ($portObj.PORT + $i -notin $my_excl) {
                $my_ports += $portObj.PORT + $i
            }
        }
    }
    $my_ports = @($my_ports | Sort-Object | Select -Unique)
    $new_ports = @()
    $index = 1
    $start = $my_ports[0]
    do {
        if (($my_ports[$index] - $my_ports[$index - 1]) -ne 1) {
            $new_ports += [PSCustomObject]@{PORT = $start; RANGE = $my_ports[$index - 1] - $start}
            $start = $my_ports[$index]
        }
        $index++
    } until ($index -eq $my_ports.length)
    $new_ports += [PSCustomObject]@{PORT = $start; RANGE = ($my_ports[$index - 1] - $start)}
    return $new_ports
}

excluded_ports
