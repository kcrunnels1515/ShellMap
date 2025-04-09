#Write-Host icmp_netmasq.ps1 "This feature has not been added."
# -PM

# Not currently possible with PowerShell (no ICMP netmask messages can be sent).
function icmp_netmask() {
    param(
        [PSCustomObject]$hostObj
    )

    $hostObj.STATUS = "Netmask not implemented"
    return
}
