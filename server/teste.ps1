$PORTS = @([PSCustomObject]@{ PORT = 80; RANGE = 0},[PSCustomObject]@{ PORT = 67; RANGE = 23},[PSCustomObject]@{ PORT = 56; RANGE = 0})
$TOP_PORTS = [int]20
Write-Host host_disc.ps1

Write-Host resolve.ps1

Write-Host randomize_ports.ps1

Write-Host service_version.ps1

Write-Host os_detect.ps1

Write-Host port_syn_scan.ps1
