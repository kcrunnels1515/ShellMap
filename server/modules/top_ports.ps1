Write-Host top_ports.ps1
# -top-ports
# Given a value n (must be less than 20) scan the top n ports

# Top 20 according to nmap (ordered most common 1st): 
# (80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900)
return $PORTS