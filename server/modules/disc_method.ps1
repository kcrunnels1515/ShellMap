function disc_method() {
    param(
        [IPAddress]$hostIP
    )
    &$DISC_METHOD $hostIP
}
