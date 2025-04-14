# -sn
# Requires input of a resolved IP ($hostIP)

# This is the basic host discovery WITHOUT port scanning following it

# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function ping_scan() {
    param(
        [IPAddress]$hostIP
    )

    $pingResults = Test-Connection -ComputerName $hostIP -Count 1 -ErrorAction SilentlyContinue
    if($pingResults)
    {
        return @{STATUS = 1; LATENCY = "$($pingResults.ResponseTime) ms" }
    } else {
        return @{STATUS = -1; LATENCY = "timeout" }
    }
}
