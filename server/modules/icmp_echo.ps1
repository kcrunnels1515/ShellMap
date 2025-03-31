Write-Host icmp_echo.ps1
# -PE
# Requires input of a resolved IP ($HOSTIP)

# Since ShellMap already utilizes ICMP to do host discovery, ICMP echo scans will reuse that behavior:

# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
$pingResults = Test-Connection $HOSTIP -Count 1 -ErrorAction SilentlyContinue
if($pingResults)
{
    $status = "TRUE"
    $latency = "$($pingResults.ResponseTime) ms"
} else {
    $status = "FALSE"
}

# Return an object including host activity (TRUE or FALSE) and latency for that host (ping time)
return [PSCustomObject]@{
    STATUS = $status
    LATENCY = $latency
}