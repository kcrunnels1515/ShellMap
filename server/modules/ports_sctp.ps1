#Write-Host ports_sctp.ps1 "This feature has not been added."
# -PY
# ShellMap is TCP ports only.
function port_sctp_scan(){
    param(
        [IPAddress]$hostIP,
        $ports
    )
    $res = @()

    $sctp_scan_scr = {
        param(
            [IPAddress]$hostIP,
            [int]$port
        )
        return [PSCustomObject]@{PORT = $port; STATUS = "SCTP scan not supported"; SERVICE = "unknown"}
    }

    foreach ($p in $ports) {
        $res += port_range($p, $hostIP, $sctp_scan_scr)
    }
    return $res
}
