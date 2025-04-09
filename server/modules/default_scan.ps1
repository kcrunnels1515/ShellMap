# default scan type, is updated by the user input (by default do a con scan)
function default_scan() {
    param(
        [IPAddress]$hostIP
    )
    &$DEFAULT_SCAN $hostIP $PORTS
}
