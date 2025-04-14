#Write-Host icmp_netmasq.ps1 "This feature has not been added."
# -PM

# Not currently possible with PowerShell (no ICMP netmask messages can be sent).
function icmp_netmasq() {
    param(
        [IPAddress]$hostIP
    )
    write-output "ICMP Netmasq not implemented"
    return @{STATUS = 0; LATENCY = ""}
}
