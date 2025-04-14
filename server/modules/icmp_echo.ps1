#Write-Host icmp_echo.ps1
# -PE
# Requires input of a resolved IP ($HOSTIP)

# Since ShellMap already utilizes ICMP to do host discovery, ICMP echo scans will reuse that behavior:

# Updates the variables of the object: hostDisc!!!
# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function icmp_echo() {
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
