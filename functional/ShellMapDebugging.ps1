Import-Module $PSScriptRoot\modules\SubNet-Calculate.psm1
Import-Module $PSScriptRoot\modules\Host-DiscoveryDebug.psm1
Import-Module $PSScriptRoot\modules\Port-ScanningDebug.psm1

$startTime = Get-Date -Format "yyyy-MM-dd HH:mm"
$timeZone = (Get-TimeZone).StandardName
Write-Output "Starting ShellMap at $startTime $timeZone"

$baseAddress = "scanme.nmap.org" # UPDATED WITH ARG INPUT (test = scanme.nmap.org)
$subNet = 30 # ALSO UPDATE WITH ARGS!

# Check if input is a hostname, resolve it to a ip address before continuing:
# ONLY get the IPv4 (for the subnet calculator!)
$resolvedIP = (Resolve-DnsName -Name $baseAddress -Type A | Select-Object -First 1).IPAddress


# Start of scan output (and / for sub)
if($subNet -eq 0)
{
    Write-Output "ShellMap scan report for $resolvedIP"
} else 
{
    Write-Output "ShellMap scan report for $resolvedIP/$subNet"
}

# Resolve the subnet using the process from SubNet-Calculate.psm1
# TO ADD: Threading for each subnet check(parallel)
# Switch statement to pick either host discovery or port scanning
$maxPos = 1 -shl (32 - $subNet)
for ( $i = 0; $i -lt $maxPos; $i++) 
{
    $ipAddress = Get-IPSubnet $resolvedIP $subNet $i
    # Swtich statement to handle which function to use (host or port!):
    # based off of the input flags! Will establish a visual of this later!

    # Write-HostDiscovery $ipAddress
    $outputs = Get-ActiveHostObject $ipAddress
    $outputs | Format-Table -Property STATUS, LATENCY -AutoSize

    #Write-PortScanning $ipAddress # Can add later the specific ports!

}

