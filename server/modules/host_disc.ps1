# -Pn
# Requires input of a resolved IP ($HOSTIP) and list of ports ($PORTS)

# Host discovery, default is ON, turned to OFF if the flag is set

# Identical to ping_scan due to the the implementation style:
# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function host_disc() {
    param(
        [PSCustomObject]$hostObj
    )
    $disc_res = disc_method($hostObj.HOST)
    $hostObj.HOSTSTATUS = $disc_res.STATUS
    $hostObj.LATENCY = $disc_res.LATENCY
    return
}
