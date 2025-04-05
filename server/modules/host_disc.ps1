Write-Host host_disc.ps1 
# -Pn
# Requires input of a resolved IP ($HOSTIP) and list of ports ($PORTS)

# Host discovery, default is ON, turned to OFF if the flag is set

# Identical to ping_scan due to the the implementation style:
# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
$pingResults = Test-Connection $hostIP -Count 1 -ErrorAction SilentlyContinue
if($pingResults)
{
    $hostStatus = "TRUE"
    $latency = "$($pingResults.ResponseTime) ms"
} else {
    $hostStatus = "FALSE"
}
