Write-Host ping_scan.ps1
# -sn
# Requires input of a resolved IP ($hostIP)

# This is the basic host discovery WITHOUT port scanning following it

# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
$pingResults = Test-Connection $hostIP -Count 1 -ErrorAction SilentlyContinue
if($pingResults)
{
    $hostStatus = "TRUE"
    $latency = "$($pingResults.ResponseTime) ms"
} else {
    $hostStatus = "FALSE"
}
