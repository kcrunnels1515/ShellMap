
# NOTES: I was previously doing port scanning ideas within host discovery, moved here.

# Store the output from the actual host discovery process in data structure to pull from later and output to user:
# HashTable -> Key = Ip/Subnet, Value = Array of objects (pingCheck, portCheck, ackCheck, timeStamp) | Format-Table (allows output to be formatted)
# $outputTable = @{}    
 # Note: it is possible for host to be down but the port open since port check is separate (not whole system health)
#     # TCP SYN Packet to port 443: "TCPTest Succeeded", true = open, false = closed
#     $portCheck = Test-NetConnection $ipAddress -Port 433 -InformationLevel:Quiet
    
#     # TCP ACK /9Test-NetConnection! (Port 80 if no port is specified!) 
# ### NOTE: TO ADD IF STATEMENT FOR IF THERE IS AN ARGUMENT FOR A PORT INCLUDED! CHANGE THE ACK HANDSHAKE TO THAT PORT!
#     $ackCheck = Test-NetConnection $ipAddress -Port 80 -InformationLevel:Quiet
#     # $ackCheck 


#     # ICMP Timestamp (ROUGH ESTIMATE) Using ICMP Echo + current user's date/time

#     $outputValues = [PSCustomObject]@{
#         pingCheck = $pingCheck
#         portCheck = $portCheck
#         ackCheck = $ackCheck
#     }
#     # Add the outputs to the output table to be read!
#     $outputTable[$ipAddress] = $outputValues