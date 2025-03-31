Write-Host list_scan.ps1
# -sL
# Requires input of a resolved IP ($HOSTIP)

# List scans simply list each host on a network, without sending packets; simply a good sanity check for domains/IPs.
$hostWebName = (Resolve-DnsName -Name $HOSTIP).NameHost
return $hostWebName