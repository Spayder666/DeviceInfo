package com.deviceinfo.trafficmonitor.monitor

object MonitorPaths {
    const val BASE = "/data/local/tmp/access_monitor"
    const val PCAP = "$BASE/am.pcap"
    const val TCPDUMP_PID = "$BASE/tcpdump.pid"
    const val PERFETTO_CFG = "$BASE/perfetto.cfg"
    const val PERFETTO_OUT = "$BASE/trace.pftrace"
}
