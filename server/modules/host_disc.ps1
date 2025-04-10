# -Pn
# Requires input of a resolved IP ($HOSTIP) and list of ports ($PORTS)

# Host discovery, default is ON, turned to OFF if the flag is set

# Identical to ping_scan due to the the implementation style:
# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function host_disc() {
    param(
        [PSCustomObject]$hostObj
    )
    if (Test-Path function:global:list_scan) {
        return
    }

    $pingResults = Test-Connection -ComputerName $hostObj.HOST -Count 1 -ErrorAction SilentlyContinue
    if($pingResults)
    {
        $hostObj.HOSTSTATUS = $true
        $hostObj.LATENCY = "$($pingResults.ResponseTime) ms"
    } else {
        $hostObj.HOSTSTATUS = $false
        $hostObj.LATENCY = "timeout"
    }
    return
}
