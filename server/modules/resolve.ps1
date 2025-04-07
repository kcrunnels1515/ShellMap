#Write-Host resolve.ps1
# -n 
# Takes in a base ipAddress for host

# The flag "-n" turns this script to FALSE, and disables resolving the hostname:
# (Tells Nmap to never do reverse DNS resolution on the active IP addresses it finds)

# Resolve the DNS name for the given HOSTS.BASE_HOST (selects the top 1)
function resolve() {
    param(
        [PSCustomObject]$hostObj
    )
    return (Resolve-DnsName -Name $hostObj.BASE_HOST -Type A | Select-Object -First 1).IPAddress
}
