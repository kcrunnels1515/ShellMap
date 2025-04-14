# -sL
# Requires input of an IP ($_BASE_HOST)

# List scans simply list each host on a network, without sending packets; simply a good sanity check for domains/IPs.
function list_scan () {
    param(
        $hostIP
    )
    return @{STATUS = 0; LATENCY = ""}
}
