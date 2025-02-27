Import-Module $PSScriptRoot\modules\SubNet-Calculate.psm1
Import-Module $PSScriptRoot\modules\Host-Discovery.psm1
Import-Module $PSScriptRoot\modules\Port-Scanning.psm1

$startTime = Get-Date -Format "yyyy-MM-dd HH:mm"
$timeZone = (Get-TimeZone).StandardName
Write-Output "Starting ShellMap at $startTime $timeZone"

$baseAddress = "google.com" # UPDATED WITH ARG INPUT
$subNet = 0 # ALSO UPDATE WITH ARGS!

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

# Swtich statement to handle which function to use (host or port!):
# based off of the input flags! Will establish a visual of this later!

# Write-HostDiscovery $baseAddress $subNet

Write-PortScanning $resolvedIP $subNet # Can add later the specific ports!
