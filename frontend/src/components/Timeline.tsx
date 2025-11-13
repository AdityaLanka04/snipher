import { useMemo } from 'react'
import './Timeline.css'

interface Packet {
  timestamp: string
  protocol: string
  length: number
}

interface TimelineProps {
  packets: Packet[]
}

export default function Timeline({ packets }: TimelineProps) {
  const timelineData = useMemo(() => {
    if (packets.length === 0) return []

    const buckets = new Map<number, { count: number; bytes: number; protocols: Set<string> }>()
    const bucketSize = 1000 // 1 second buckets

    packets.forEach(packet => {
      const time = new Date(packet.timestamp).getTime()
      const bucket = Math.floor(time / bucketSize) * bucketSize

      const existing = buckets.get(bucket)
      if (existing) {
        existing.count++
        existing.bytes += packet.length
        existing.protocols.add(packet.protocol)
      } else {
        buckets.set(bucket, {
          count: 1,
          bytes: packet.length,
          protocols: new Set([packet.protocol])
        })
      }
    })

    const sorted = Array.from(buckets.entries())
      .sort(([a], [b]) => a - b)
      .slice(-60) // Last 60 seconds

    const maxCount = Math.max(...sorted.map(([, data]) => data.count), 1)

    return sorted.map(([time, data]) => ({
      time,
      count: data.count,
      bytes: data.bytes,
      height: (data.count / maxCount) * 100,
      protocols: Array.from(data.protocols)
    }))
  }, [packets])

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString()
  }

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  return (
    <div className="timeline">
      <h3>Traffic Timeline</h3>
      <div className="timeline-chart">
        {timelineData.map((point, idx) => (
          <div
            key={idx}
            className="timeline-bar"
            style={{ height: `${point.height}%` }}
            title={`${formatTime(point.time)}\n${point.count} packets\n${formatBytes(point.bytes)}\n${point.protocols.join(', ')}`}
          >
            <div className="timeline-bar-fill" />
          </div>
        ))}
      </div>
      <div className="timeline-labels">
        <span>Traffic over time (last 60s)</span>
      </div>
    </div>
  )
}
