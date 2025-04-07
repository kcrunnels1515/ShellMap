#Write-Host port_ack_scan.ps1 "This feature has not been added."
# -sA
# This feature is currently not reachable due to blockers of PowerShell.
function port_ack_scan(){
    param(
        [IPAddress]$hostIP,
        $ports
    )
    $res = @()

    $ack_scan_scr = {
        param(
            [IPAddress]$hostIP,
            [int]$port
        )
        return [PSCustomObject]@{PORT = $port; STATUS = "ACK scan not supported"; SERVICE = "unknown"}
    }

    foreach ($p in $ports) {
        $res += port_range($p, $hostIP, $ack_scan_scr)
    }
    return $res
}
