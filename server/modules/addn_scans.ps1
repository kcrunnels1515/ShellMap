function addn_scans() {
    $ADDN_SCANS = @()
    if (Test-Path variable:global:PORTS_ACK) {
        $ADDN_SCANS += [PSCustomObject]@{FN = (Get-Item -Path 'Function:\port_ack_scan'); VAL = $PORTS_ACK}
    }
    if (Test-Path variable:global:PORTS_SYN) {
        $ADDN_SCANS += [PSCustomObject]@{FN = (Get-Item -Path 'Function:\port_syn_scan'); VAL = $PORTS_SYN}
    }
    if (Test-Path variable:global:PORTS_UDP) {
        $ADDN_SCANS += [PSCustomObject]@{FN = (Get-Item -Path 'Function:\port_udp_scan'); VAL = $PORTS_UDP}
    }
    return $ADDN_SCANS
}
