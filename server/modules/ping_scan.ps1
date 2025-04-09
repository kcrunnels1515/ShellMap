# -sn
# Requires input of a resolved IP ($hostIP)

# This is the basic host discovery WITHOUT port scanning following it

# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function ping_scan() {
    param(
        [IPAddress]$hostIP,
        $ports
    )
    return
}
