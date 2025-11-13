import { useMemo } from 'react'
import './Statistics.css'

interface Packet {
  protocol: string
  length: number
  timestamp: string
}

interface StatisticsProps {
  packets: Packet[]
  isCapturing: boolean
}

export default function Statistics({ packets, isCapturing }: StatisticsProps) {
  const stats = useMemo(() => {
    const protocolCounts: Record<string, number> = {}
    const protocolBytes: Record<string, number> = {}
    let totalBytes = 0

    packets.forEach(packet => {
      protocolCounts[packet.protocol] = (protocolCounts[packet.protocol] || 0) + 1
      protocolBytes[packet.protocol] = (protocolBytes[packet.protocol] || 0) + packet.length
      totalBytes += packet.length
    })

    const sortedProtocols = Object.entries(protocolCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)

    // Calculate packets per second
    let packetsPerSecond = 0
    if (packets.length > 1) {
      const firstTime = new Date(packets[0].timestamp).getTime()
      const lastTime = new Date(packets[packets.length - 1].timestamp).getTime()
      const duration = (lastTime - firstTime) / 1000
      packetsPerSecond = duration > 0 ? packets.length / duration : 0
    }

    return {
      totalPackets: packets.length,
      totalBytes,
      protocolCounts: sortedProtocols,
      protocolBytes,
      packetsPerSecond,
      avgPacketSize: packets.length > 0 ? totalBytes / packets.length : 0
    }
  }, [packets])

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  const getProtocolColor = (protocol: string) => {
    const colors: Record<string, string> = {
      'TCP': '#4a9eff',
      'UDP': '#ffa94a',
      'HTTP': '#4aff88',
      'HTTPS': '#3aff78',
      'DNS': '#ff4a9e',
      'ICMP': '#ff4a4a',
      'ICMPv6': '#ff6a6a',
      'ARP': '#9e4aff',
      'SSH': '#4affff',
      'FTP': '#ffff4a',
      'DHCP': '#8a4aff',
      'NTP': '#4aff9e',
      'IPv6': '#6a9eff',
      'MySQL': '#4a8aff',
      'PostgreSQL': '#6a4aff',
    }
    return colors[protocol] || '#888'
  }

  return (
    <div className="statistics">
      <div className="stats-header">
        <h3>Statistics</h3>
        {isCapturing && <span className="live-indicator">● LIVE</span>}
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Packets</div>
          <div className="stat-value">{stats.totalPackets.toLocaleString()}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Total Data</div>
          <div className="stat-value">{formatBytes(stats.totalBytes)}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Packets/sec</div>
          <div className="stat-value">{stats.packetsPerSecond.toFixed(1)}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Avg Size</div>
          <div className="stat-value">{formatBytes(stats.avgPacketSize)}</div>
        </div>
      </div>

      <div className="protocol-breakdown">
        <h4>Protocol Distribution</h4>
        <div className="protocol-list">
          {stats.protocolCounts.map(([protocol, count]) => {
            const percentage = (count / stats.totalPackets) * 100
            const bytes = stats.protocolBytes[protocol]
            return (
              <div key={protocol} className="protocol-item">
                <div className="protocol-info">
                  <span
                    className="protocol-dot"
                    style={{ backgroundColor: getProtocolColor(protocol) }}
                  />
                  <span className="protocol-name">{protocol}</span>
                  <span className="protocol-count">{count}</span>
                </div>
                <div className="protocol-bar-container">
                  <div
                    className="protocol-bar"
                    style={{
                      width: `${percentage}%`,
                      backgroundColor: getProtocolColor(protocol)
                    }}
                  />
                </div>
                <div className="protocol-stats">
                  <span>{percentage.toFixed(1)}%</span>
                  <span>{formatBytes(bytes)}</span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
