Write-Host randomize_ports.ps1
# -r
# Requires that $PORTS is already set by default

# By default this is off: (the port order is random rather than sequential)
# This reorders them sequentially.
$outputPorts = $PORTS | Sort-Object
return $outputPorts