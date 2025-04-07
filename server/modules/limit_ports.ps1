#Write-Host limit_ports.ps1
# -F

# This will change the port list to just top 5 rather than top 20 (Nmap goes from top 1000 -> 100)
function limit_ports() {
    return ($PORTS | Select-Object -First 5)
}
