Import-Module $PSScriptRoot\SubNet-Calculate.psm1

# Overview/Concept: 
# FIRST: Establish what hosts are even available (host discovery) (ensure efficiency)
# Then connect to ports on those:
# Use a TCP cliet (dot net TCP) to send a handshake to a port (SYN) 
# SYN/ACK: The target responds with a SYN/ACK packet if the port is open. 
# RST: If the port is closed, the target responds with a RST packet. 
# No response: If no response is received, the port is considered filtered. 
# Basic scan (unspecified ports will scan all 65535 ports or 80, 443, 21, 22, 23) UNDECIDED
# Open = application is responding to TCP (or UDP) ** Primary goal of port scanning
# Closed = application is responding to TCP (or UDP) BUT, it is not listening (no service active)
# Filtered = No response, and 
# Unfiltered = 

function Write-PortScanning([ipaddress]$resolvedIP, [int]$subNet)
{
    # Use host discovery to get the subnet + the active IPs!! (THIS ALSO DEPENDS ON THE FLAG SET, BUT THIS IS DEFAULT)
    # NOTE: Could add a flag that changes to check ALL hosts since "inactive" doesn't necessarily = not port accessible
    $ipAddresses = Get-ActiveHosts $resolvedIP $subNet

    # Establish a table to hold all the outputs: PORT, STATE, SERVICE 
    # Store the output from the actual host discovery process in data structure to pull from later and output to user:
    # HashTable -> Key = Ip/Subnet, Value = Array of objects () | Format-Table (allows output to be formatted)
    $outputTable = @{}    
    # Note: it is possible for host to be down but the port open since port check is separate (not whole system health)

    # TCP Client Setup:
    $ports = @(80, 443, 21, 22, 23)  # Replace with port (if input, can add to args later!)

    $startTime = Get-Date
    foreach($ipAddress in $ipAddresses) 
    {
        $open = $false # AUTO SET THE PORT TO CLOSED, ONLY UPDATE IF OPEN!
        # Create a TCP client
        $tcpClient = New-Object System.Net.Sockets.TcpClient

        # Connect to the server using the IP address and specified port
        foreach($port in $ports)
        {
            # If the client connects to the port, this means the port is open AND listening:
            $tcpClient.Connect($resolvedIP, $port)
            if ($tcpClient.Connected) {
                # This port is open! Mark as open!
                $open = $true
                # Close TCP Client!
                $tcpClient.Close()
            } else 
            {
                # The port isn't listening (though it responded) it is either closed or filtered! (don't update the open)
                
            }

            # Check if ACK scan: UNFILTERED

            $outputValues = [PSCustomObject]@{
                port = $port
                open = $open
                portCheck = $portCheck
                ackCheck = $ackCheck
            }
        }
        
    }
    $endTime = Get-Date

    $elapsedTime = ($endTime - $startTime)  
    $elapsedMs = $elapsedTime.TotalMilliseconds  

    Write-Output "ShellMap scanned in $elapsedMs ms" 
}
