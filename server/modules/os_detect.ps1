#Write-Host os_detect.ps1 "This feature has not been added."
# -O

# OS detection is a hard task to complete without admin permissions/being a trusted -
# computer of the target, so this feature has not been added.
function os_detect() {
    param(
        [PSCustomObject]$hostObj
    )
    Write-Host "OS Detection is not supported"
}
