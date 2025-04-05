Write-Host excluded_ports.ps1 
# -exclude-ports
# Require input of exclude port list ($EXCL_PORTS)
# (default port list has already been defined at this point)

# Removes any matches to ports from EXCL_PORTS from default PORTS and updates the variable
$PORTS = $PORTS | Where-Object { $EXCL_PORTS -notcontains $_}
