#Write-Host port_syn_scan.ps1 "This feature has not been added."
# -sS
# By default, ShellMap performs a CON scan rather than the SYN scan as nnmap does.
# This feature is currently not reachable due to blockers of PowerShell.
function port_syn_scan(){
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
        return [PSCustomObject]@{PORT = $port; STATUS = "SYN scan not supported"; SERVICE = "unknown"}
    }

    foreach ($p in $ports) {
        $res += port_range($p, $hostIP, $syn_scan_scr)
    }
    return $res
}
