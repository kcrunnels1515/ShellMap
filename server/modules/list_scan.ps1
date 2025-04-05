Write-Host list_scan.ps1
# -sL
# Requires input of an IP ($_BASE_HOST)

# List scans simply list each host on a network, without sending packets; simply a good sanity check for domains/IPs.
$hostName = (Resolve-DnsName -Name $hostIP).NameHost
