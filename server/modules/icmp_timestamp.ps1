#Write-Host icmp_timestamp.ps1 "This feature has not been added."
# -PP

# Not currently possible with PowerShell (no timestamp type messages can be sent).
function icmp_timestamp() {
    param(
        [PSCustomObject]$hostObj
    )

    $hostObj.STATUS = "Timestamp not implemented"
    return
}
