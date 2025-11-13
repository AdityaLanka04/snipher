import { useEffect, useRef, useState } from 'react'
import { Globe, Server, Laptop, Shield, AlertTriangle } from 'lucide-react'
import { geoIPService } from '../utils/geoip'
import './NetworkMap.css'

interface NetworkMapProps {
  packets: any[]
}

interface NetworkNode {
  id: string
  ip: string
  type: 'local' | 'remote' | 'server'
  country?: string
  packets: number
  protocols: Set<string>
  suspicious: boolean
  x: number
  y: number
}

interface NetworkConnection {
  source: string
  target: string
  packets: number
  protocols: string[]
  bandwidth: number
}

export default function NetworkMap({ packets }: NetworkMapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [nodes, setNodes] = useState<Map<string, NetworkNode>>(new Map())
  const [connections, setConnections] = useState<Map<string, NetworkConnection>>(new Map())
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null)

  useEffect(() => {
    updateNetworkData()
  }, [packets])

  useEffect(() => {
    drawNetwork()
  }, [nodes, connections])

  const updateNetworkData = () => {
    const newNodes = new Map<string, NetworkNode>()
    const newConnections = new Map<string, NetworkConnection>()

    packets.forEach(packet => {
      const srcIP = packet.src.split(':')[0]
      const dstIP = packet.dst.split(':')[0]

      // Create or update source node
      if (!newNodes.has(srcIP)) {
        newNodes.set(srcIP, {
          id: srcIP,
          ip: srcIP,
          type: getNodeType(srcIP),
          country: isPublicIP(srcIP) ? getCountryFromIP(srcIP) : undefined,
          packets: 0,
          protocols: new Set(),
          suspicious: isSuspiciousIP(srcIP, packet),
          x: Math.random() * 400 + 50,
          y: Math.random() * 300 + 50
        })
      }

      // Create or update destination node
      if (!newNodes.has(dstIP)) {
        newNodes.set(dstIP, {
          id: dstIP,
          ip: dstIP,
          type: getNodeType(dstIP),
          country: isPublicIP(dstIP) ? getCountryFromIP(dstIP) : undefined,
          packets: 0,
          protocols: new Set(),
          suspicious: isSuspiciousIP(dstIP, packet),
          x: Math.random() * 400 + 50,
          y: Math.random() * 300 + 50
        })
      }

      // Update node data
      const srcNode = newNodes.get(srcIP)!
      const dstNode = newNodes.get(dstIP)!
      
      srcNode.packets++
      dstNode.packets++
      srcNode.protocols.add(packet.protocol)
      dstNode.protocols.add(packet.protocol)

      // Create or update connection
      const connectionKey = `${srcIP}-${dstIP}`
      if (!newConnections.has(connectionKey)) {
        newConnections.set(connectionKey, {
          source: srcIP,
          target: dstIP,
          packets: 0,
          protocols: [],
          bandwidth: 0
        })
      }

      const connection = newConnections.get(connectionKey)!
      connection.packets++
      connection.bandwidth += packet.length
      if (!connection.protocols.includes(packet.protocol)) {
        connection.protocols.push(packet.protocol)
      }
    })

    setNodes(newNodes)
    setConnections(newConnections)
  }

  const drawNetwork = () => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height)

    // Draw connections
    connections.forEach(connection => {
      const sourceNode = nodes.get(connection.source)
      const targetNode = nodes.get(connection.target)
      
      if (sourceNode && targetNode) {
        ctx.beginPath()
        ctx.moveTo(sourceNode.x, sourceNode.y)
        ctx.lineTo(targetNode.x, targetNode.y)
        
        // Line thickness based on packet count
        ctx.lineWidth = Math.min(Math.max(connection.packets / 10, 1), 5)
        
        // Color based on protocols
        if (connection.protocols.includes('HTTP')) {
          ctx.strokeStyle = '#4aff88'
        } else if (connection.protocols.includes('HTTPS')) {
          ctx.strokeStyle = '#4a9eff'
        } else if (connection.protocols.includes('DNS')) {
          ctx.strokeStyle = '#ff4a9e'
        } else {
          ctx.strokeStyle = '#888'
        }
        
        ctx.stroke()

        // Draw packet count
        const midX = (sourceNode.x + targetNode.x) / 2
        const midY = (sourceNode.y + targetNode.y) / 2
        
        ctx.fillStyle = '#fff'
        ctx.font = '10px Arial'
        ctx.textAlign = 'center'
        ctx.fillText(connection.packets.toString(), midX, midY)
      }
    })

    // Draw nodes
    nodes.forEach(node => {
      ctx.beginPath()
      ctx.arc(node.x, node.y, getNodeRadius(node), 0, 2 * Math.PI)
      
      // Node color based on type and status
      if (node.suspicious) {
        ctx.fillStyle = '#ff4a4a'
      } else if (node.type === 'local') {
        ctx.fillStyle = '#4aff88'
      } else if (node.type === 'server') {
        ctx.fillStyle = '#4a9eff'
      } else {
        ctx.fillStyle = '#ffa94a'
      }
      
      ctx.fill()
      
      // Border
      ctx.strokeStyle = '#fff'
      ctx.lineWidth = 2
      ctx.stroke()

      // IP label
      ctx.fillStyle = '#fff'
      ctx.font = '12px Arial'
      ctx.textAlign = 'center'
      ctx.fillText(node.ip, node.x, node.y + getNodeRadius(node) + 15)
    })
  }

  const getNodeType = (ip: string): 'local' | 'remote' | 'server' => {
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
      return 'local'
    }
    
    // Common server IPs
    if (ip === '8.8.8.8' || ip === '1.1.1.1' || ip.includes('google') || ip.includes('cloudflare')) {
      return 'server'
    }
    
    return 'remote'
  }

  const getNodeRadius = (node: NetworkNode): number => {
    return Math.min(Math.max(node.packets / 5 + 10, 10), 30)
  }

  const isPublicIP = (ip: string): boolean => {
    return geoIPService.isPublicIP(ip)
  }

  // Use the centralized GeoIP service
  const getCountryFromIP = (ip: string): string => {
    return geoIPService.getCountryCode(ip)
  }

  const isSuspiciousIP = (ip: string, packet: any): boolean => {
    // Check for suspicious ports
    const suspiciousPorts = [1337, 31337, 4444, 5555, 6666, 7777]
    if (packet.dst_port && suspiciousPorts.includes(packet.dst_port)) return true
    
    // Check for unusual protocols
    if (packet.protocol === 'Telnet') return true
    
    return false
  }

  const handleCanvasClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current
    if (!canvas) return

    const rect = canvas.getBoundingClientRect()
    const x = event.clientX - rect.left
    const y = event.clientY - rect.top

    // Find clicked node
    for (const node of nodes.values()) {
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2)
      if (distance <= getNodeRadius(node)) {
        setSelectedNode(node)
        return
      }
    }

    setSelectedNode(null)
  }

  return (
    <div className="network-map">
      <div className="map-header">
        <Globe size={16} />
        <h3>Network Topology</h3>
        <div className="map-stats">
          <span>{nodes.size} nodes</span>
          <span>{connections.size} connections</span>
        </div>
      </div>

      <div className="map-content">
        <canvas
          ref={canvasRef}
          width={500}
          height={400}
          onClick={handleCanvasClick}
          className="network-canvas"
        />

        {selectedNode && (
          <div className="node-details">
            <div className="node-header">
              {selectedNode.type === 'local' && <Laptop size={16} />}
              {selectedNode.type === 'server' && <Server size={16} />}
              {selectedNode.type === 'remote' && <Globe size={16} />}
              {selectedNode.suspicious && <AlertTriangle size={16} className="warning" />}
              <span>{selectedNode.ip}</span>
            </div>
            
            <div className="node-info">
              <div className="info-item">
                <span>Type:</span>
                <span>{selectedNode.type}</span>
              </div>
              <div className="info-item">
                <span>Packets:</span>
                <span>{selectedNode.packets}</span>
              </div>
              <div className="info-item">
                <span>Protocols:</span>
                <span>{Array.from(selectedNode.protocols).join(', ')}</span>
              </div>
              {selectedNode.country && (
                <div className="info-item">
                  <span>Country:</span>
                  <span>{selectedNode.country}</span>
                </div>
              )}
              {selectedNode.suspicious && (
                <div className="info-item warning">
                  <Shield size={14} />
                  <span>Suspicious activity detected</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="map-legend">
        <div className="legend-item">
          <div className="legend-color local"></div>
          <span>Local Network</span>
        </div>
        <div className="legend-item">
          <div className="legend-color server"></div>
          <span>Servers</span>
        </div>
        <div className="legend-item">
          <div className="legend-color remote"></div>
          <span>Remote Hosts</span>
        </div>
        <div className="legend-item">
          <div className="legend-color suspicious"></div>
          <span>Suspicious</span>
        </div>
      </div>
    </div>
  )
}