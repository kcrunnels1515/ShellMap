# -Pn
# Requires input of a resolved IP ($HOSTIP) and list of ports ($PORTS)

# Host discovery, default is ON, turned to OFF if the flag is set

# Identical to ping_scan due to the the implementation style:
# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function host_disc() {
    param(
        [PSCustomObject]$hostObj
    )
    if ($DEFAULT_SCAN -eq (Get-Item -Path 'Function:\list_scan')) {
        return
    }

    $pingResults = Test-Connection $hostObj.HOST -Count 1 -ErrorAction SilentlyContinue
    if($pingResults)
    {
        $hostObj.STATUS = "TRUE"
        $hostObj.LATENCY = "$($pingResults.ResponseTime) ms"
    } else {
        $hostObj.STATUS = "FALSE"
    }
    return
}
