Import-Module $PSScriptRoot\SubNet-Calculate.psm1

# Concept: 
# For each ip address from the input (1+), calculate all the subnets, once the subnets are calculated, call ping through the whole list.
# Output the successfully pinged ip addresses (hosts that are up)

function Write-HostDiscovery([ipaddress]$ipAddress)
{
    Write-Output "Scanning IP $resolvedIP"

    $activeHosts = 0
    $activePrintCount = 0
    $numAddresses = $ipAddresses.Count

    $startTime = Get-Date
    # ICMP echo request (PING): with -Quiet to do basic ping (and count of 1 to send 1 ping packet)
    # NOTE: If we want to add it: different ping depending on the input flag (generic is ICMP echo)
    $pingCheck = Test-Connection $ipAddress -Quiet -Count 1
    # Add to the count of active hosts if the ping is TRUE:
    if($pingCheck)
    {
        Write-Output "Host $ipAddress appears to be up."
    } else 
    {
        Write-Output "Host $ipAddress appears to be down."
    }
    
    $endTime = Get-Date 

    $elapsedTime = ($endTime - $startTime)  
    $elapsedMs = $elapsedTime.TotalMilliseconds  

    Write-Output "ShellMap done: $numAddresses IP address ($activeHosts hosts up) scanned in $elapsedMs ms" 

}

# Return IP's for all the active hosts (to be used in port scanning)
function Get-ActiveHost([ipaddress]$ipAddress)
{
    # ICMP echo request (PING): with -Quiet to do basic ping (and count of 1 to send 1 ping packet)
    $pingCheck = Test-Connection $ipAddress -Quiet -Count 1
    # Add to the count of active hosts if the ping is TRUE:
    if($pingCheck)
    {
        return $true
    }

    return $false
}

function Get-ActiveHostObject([ipaddress]$ipAddress)
{
    $hostName = (Resolve-DnsName -Name $ipAddress).NameHost
    Write-Host $hostName
    # ICMP echo request (PING): with select to only get the PingCheck and ResponseTime (latency), silently continue if errors (host down)
    $pingResults = Test-Connection $ipAddress -Count 1 -ErrorAction SilentlyContinue
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
}

