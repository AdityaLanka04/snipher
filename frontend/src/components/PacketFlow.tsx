import { useMemo } from 'react'
import './PacketFlow.css'

interface Packet {
  src: string
  dst: string
  protocol: string
  length: number
  timestamp: string
}

interface PacketFlowProps {
  packets: Packet[]
}

interface Connection {
  src: string
  dst: string
  protocol: string
  count: number
  bytes: number
  firstSeen: string
  lastSeen: string
}

export default function PacketFlow({ packets }: PacketFlowProps) {
  const connections = useMemo(() => {
    const connMap = new Map<string, Connection>()

    packets.forEach(packet => {
      const key = `${packet.src}-${packet.dst}-${packet.protocol}`
      const existing = connMap.get(key)

      if (existing) {
        existing.count++
        existing.bytes += packet.length
        existing.lastSeen = packet.timestamp
      } else {
        connMap.set(key, {
          src: packet.src,
          dst: packet.dst,
          protocol: packet.protocol,
          count: 1,
          bytes: packet.length,
          firstSeen: packet.timestamp,
          lastSeen: packet.timestamp
        })
      }
    })

    return Array.from(connMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 20)
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
      'IPv6': '#6a9eff',
    }
    return colors[protocol] || '#888'
  }

  return (
    <div className="packet-flow">
      <h3>Connection Flow</h3>
      <div className="flow-list">
        {connections.map((conn, idx) => (
          <div key={idx} className="flow-item">
            <div className="flow-header">
              <span
                className="flow-protocol"
                style={{ backgroundColor: getProtocolColor(conn.protocol) }}
              >
                {conn.protocol}
              </span>
              <span className="flow-count">{conn.count} packets</span>
            </div>
            <div className="flow-connection">
              <div className="flow-endpoint src">{conn.src}</div>
              <div className="flow-arrow">→</div>
              <div className="flow-endpoint dst">{conn.dst}</div>
            </div>
            <div className="flow-stats">
              <span>{formatBytes(conn.bytes)}</span>
              <span className="flow-duration">
                {((new Date(conn.lastSeen).getTime() - new Date(conn.firstSeen).getTime()) / 1000).toFixed(1)}s
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
