#Write-Host ports_udp.ps1 "This feature has not been added."
# -PU
# Not possible with PowerShell (ShellMap is TCP ports only).
function port_udp_scan(){
    param(
        [IPAddress]$hostIP,
        $ports
    )
    $res = @()

    $syn_scan_scr = {
        param(
            [IPAddress]$hostIP,
            [int]$port
        )
        return [PSCustomObject]@{PORT = $port; STATUS = "UDP scan not supported"; SERVICE = "unknown"}
    }

    foreach ($p in $ports) {
        $res += port_range($p, $hostIP, $syn_scan_scr)
    }
    return $res
}
