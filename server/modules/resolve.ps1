Write-Host resolve.ps1
# -n 
# Takes in a base ipAddress

# The flag "-n" turns this script to FALSE, and disables resolving the hostname:
# (Tells Nmap to never do reverse DNS resolution on the active IP addresses it finds)

# Resolve the DNS name for the given ipAddress (selects the top 1)
return (Resolve-DnsName -Name $ipAddress -Type A | Select-Object -First 1).IPAddress