#Write-Host icmp_echo.ps1
# -PE
# Requires input of a resolved IP ($HOSTIP)

# Since ShellMap already utilizes ICMP to do host discovery, ICMP echo scans will reuse that behavior:

# Updates the variables of the object: hostDisc!!!
# ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
function icmp_echo() {
    param(
        [PSCustomObject]$hostObj
    )
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
