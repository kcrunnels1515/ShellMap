# This is a placeholder script it will be called at the end of concatenating all the others (IN THE EXECUTABLE LOOP),
# and finalize the variables to be output by calling upon values set in the scripts!

$output = [PSCustomObject]@{
    HOST = $hostIP
    HOSTNAME = $hostName

    HOSTSTATUS = $hostStatus # the name of this column will never be used (Host ---- is "up/down" is the message)
    LATENCY = $latency

    PORT = $port
    STATUS = $portStatus
    SERVICE = $service
}
