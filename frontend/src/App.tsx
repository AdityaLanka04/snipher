import { useState, useEffect, useRef } from 'react'
import { Play, Square, Trash2, Filter, Download, Network, BarChart3, Sliders, Save, Shield, Globe, Layers } from 'lucide-react'
import Statistics from './components/Statistics'
import PacketFlow from './components/PacketFlow'
import Timeline from './components/Timeline'
import AdvancedFilters, { FilterConfig } from './components/AdvancedFilters'
import StreamViewer from './components/StreamViewer'
import SecurityAnalyzer from './components/SecurityAnalyzer'
import NetworkMap from './components/NetworkMap'
import PacketDissector from './components/PacketDissector'
import FilterHelper from './components/FilterHelper'
import './App.css'

interface Packet {
  timestamp: string
  length: number
  protocol: string
  src: string
  dst: string
  src_port?: number
  dst_port?: number
  info: string
  raw: string
  layers?: string[]
  tcp_flags?: string
  seq?: number
  ack?: number
  ttl?: number
  icmp_type?: number
  icmp_code?: number
  dns_query?: string
  dns_answers?: string[]
  http_method?: string
  http_host?: string
  http_path?: string
  src_mac?: string
  dst_mac?: string
}

function App() {
  const [packets, setPackets] = useState<Packet[]>([])
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null)
  const [isCapturing, setIsCapturing] = useState(false)
  const [filter, setFilter] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [interfaces, setInterfaces] = useState<string[]>([])
  const [selectedInterface, setSelectedInterface] = useState<string>('')
  const [showStats, setShowStats] = useState(true)
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false)
  const [advancedFilters, setAdvancedFilters] = useState<FilterConfig | null>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [maxPackets, setMaxPackets] = useState(1000)
  const [streamToFollow, setStreamToFollow] = useState<string | null>(null)
  const [activeView, setActiveView] = useState<'stats' | 'security' | 'network' | 'dissector'>('stats')
  const wsRef = useRef<WebSocket | null>(null)
  const packetListRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchInterfaces()
    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [])

  const fetchInterfaces = async () => {
    try {
      const response = await fetch('/api/interfaces')
      const data = await response.json()
      setInterfaces(data.interfaces)
      if (data.interfaces.length > 0) {
        setSelectedInterface(data.interfaces[0])
      }
    } catch (error) {
      console.error('Failed to fetch interfaces:', error)
    }
  }

  const connectWebSocket = () => {
    const ws = new WebSocket('ws://localhost:8000/ws')
    
    ws.onopen = () => {
      console.log('WebSocket connected')
    }
    
    ws.onmessage = (event) => {
      const packet = JSON.parse(event.data)
      setPackets(prev => {
        const updated = [...prev, packet]
        // Limit packets to maxPackets
        return updated.length > maxPackets ? updated.slice(-maxPackets) : updated
      })
      
      // Auto-scroll to bottom
      if (autoScroll && packetListRef.current) {
        packetListRef.current.scrollTop = packetListRef.current.scrollHeight
      }
    }
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
    }
    
    ws.onclose = () => {
      console.log('WebSocket disconnected')
      wsRef.current = null
    }
    
    wsRef.current = ws
  }

  const startCapture = async () => {
    try {
      const response = await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: selectedInterface || null,
          filter: filter || null
        })
      })
      
      if (response.ok) {
        setIsCapturing(true)
        connectWebSocket()
      }
    } catch (error) {
      console.error('Failed to start capture:', error)
    }
  }

  const stopCapture = async () => {
    try {
      await fetch('/api/capture/stop', { method: 'POST' })
      setIsCapturing(false)
      
      if (wsRef.current) {
        wsRef.current.close()
      }
    } catch (error) {
      console.error('Failed to stop capture:', error)
    }
  }

  const clearPackets = () => {
    setPackets([])
    setSelectedPacket(null)
  }

  const exportPackets = () => {
    const dataStr = JSON.stringify(packets, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `packets_${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  const exportPCAP = async () => {
    try {
      const response = await fetch('/api/export/pcap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packets: packets.slice(-100) })
      })
      
      if (response.ok) {
        const blob = await response.blob()
        const url = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `capture_${new Date().toISOString().replace(/[:.]/g, '-')}.pcap`
        link.click()
        URL.revokeObjectURL(url)
      }
    } catch (error) {
      console.error('Failed to export PCAP:', error)
    }
  }

  const handleAdvancedFilters = (filters: FilterConfig) => {
    setAdvancedFilters(filters)
  }

  const clearAdvancedFilters = () => {
    setAdvancedFilters(null)
  }

  const filteredPackets = packets.filter(packet => {
    // BPF-style filter (applied at backend, but we can also filter frontend for search)
    // Search term filter with enhanced matching
    if (searchTerm) {
      const search = searchTerm.toLowerCase().trim()
      
      // Handle BPF-style expressions in search
      if (search.includes('port ')) {
        const portMatch = search.match(/port\s+(\d+)/)
        if (portMatch) {
          const port = parseInt(portMatch[1])
          if (packet.src_port !== port && packet.dst_port !== port) {
            return false
          }
        }
      } else if (search.includes('host ')) {
        const hostMatch = search.match(/host\s+([\d.]+)/)
        if (hostMatch) {
          const host = hostMatch[1]
          if (!packet.src.includes(host) && !packet.dst.includes(host)) {
            return false
          }
        }
      } else if (search.includes('net ')) {
        const netMatch = search.match(/net\s+([\d.]+)/)
        if (netMatch) {
          const net = netMatch[1]
          if (!packet.src.startsWith(net) && !packet.dst.startsWith(net)) {
            return false
          }
        }
      } else if (search.includes('tcp port ')) {
        const portMatch = search.match(/tcp\s+port\s+(\d+)/)
        if (portMatch) {
          const port = parseInt(portMatch[1])
          if (packet.protocol !== 'TCP' && packet.protocol !== 'HTTP' && packet.protocol !== 'HTTPS') {
            return false
          }
          if (packet.src_port !== port && packet.dst_port !== port) {
            return false
          }
        }
      } else if (search.includes('udp port ')) {
        const portMatch = search.match(/udp\s+port\s+(\d+)/)
        if (portMatch) {
          const port = parseInt(portMatch[1])
          if (packet.protocol !== 'UDP' && packet.protocol !== 'DNS') {
            return false
          }
          if (packet.src_port !== port && packet.dst_port !== port) {
            return false
          }
        }
      } else {
        // Regular text search
        const matches = (
          packet.protocol.toLowerCase().includes(search) ||
          packet.src.toLowerCase().includes(search) ||
          packet.dst.toLowerCase().includes(search) ||
          packet.info.toLowerCase().includes(search) ||
          (packet.src_port && packet.src_port.toString().includes(search)) ||
          (packet.dst_port && packet.dst_port.toString().includes(search)) ||
          (packet.tcp_flags && packet.tcp_flags.toLowerCase().includes(search))
        )
        if (!matches) return false
      }
    }

    // Advanced filters
    if (advancedFilters) {
      if (advancedFilters.protocols.length > 0 && !advancedFilters.protocols.includes(packet.protocol)) {
        return false
      }
      if (packet.length < advancedFilters.minLength || packet.length > advancedFilters.maxLength) {
        return false
      }
      if (advancedFilters.srcIp && !packet.src.includes(advancedFilters.srcIp)) {
        return false
      }
      if (advancedFilters.dstIp && !packet.dst.includes(advancedFilters.dstIp)) {
        return false
      }
      if (advancedFilters.srcPort && packet.src_port?.toString() !== advancedFilters.srcPort) {
        return false
      }
      if (advancedFilters.dstPort && packet.dst_port?.toString() !== advancedFilters.dstPort) {
        return false
      }
    }

    return true
  })

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
      'TLS': '#ff9e4a',
      'SSH': '#4affff',
      'FTP': '#ffff4a',
      'SMTP': '#ff8a4a',
      'DHCP': '#8a4aff',
      'NTP': '#4aff9e',
      'SNMP': '#9eff4a',
      'MySQL': '#4a8aff',
      'PostgreSQL': '#6a4aff',
      'Redis': '#ff4a8a',
      'MongoDB': '#8aff4a',
      'IPv6': '#6a9eff',
      'Ethernet': '#666',
      'BOOTP': '#aa4aff',
      'Syslog': '#ffaa4a',
      'STP': '#4affaa',
      'LLC': '#777',
      'SNAP': '#888',
      'POP3': '#ff6aaa',
      'IMAP': '#aa6aff',
      'AMQP': '#6aaaff',
      'Elasticsearch': '#ffaa6a',
      'mDNS': '#aa4aaa',
      'SSDP': '#4aaaaa',
    }
    return colors[protocol] || '#888'
  }

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const formatHexDump = (hex: string) => {
    if (!hex) return ''
    const bytes = hex.split(' ')
    let result = ''
    for (let i = 0; i < bytes.length; i += 16) {
      const offset = i.toString(16).padStart(4, '0')
      const hexPart = bytes.slice(i, i + 16).join(' ').padEnd(47, ' ')
      const asciiPart = bytes.slice(i, i + 16).map(b => {
        const code = parseInt(b, 16)
        return (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.'
      }).join('')
      result += `${offset}  ${hexPart}  ${asciiPart}\n`
    }
    return result
  }

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <Network size={24} />
          <h1>Snipher</h1>
        </div>
        <div className="header-stats">
          <div className="stat-item">
            <span className="stat-label">Packets</span>
            <span className="stat-value">{packets.length.toLocaleString()}</span>
          </div>
          <div className={`status-indicator ${isCapturing ? 'status-active' : 'status-inactive'}`}>
            <span>{isCapturing ? 'Capturing' : 'Stopped'}</span>
          </div>
        </div>
      </header>

      <div className="toolbar">
        <div className="toolbar-left">
          <select
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={isCapturing}
            className="interface-select"
          >
            {interfaces.map(iface => (
              <option key={iface} value={iface}>{iface}</option>
            ))}
          </select>
          
          <button
            onClick={isCapturing ? stopCapture : startCapture}
            className={`btn ${isCapturing ? 'btn-danger' : 'btn-primary'}`}
          >
            {isCapturing ? <Square size={16} /> : <Play size={16} />}
            {isCapturing ? 'Stop' : 'Start'}
          </button>
          
          <button onClick={clearPackets} className="btn btn-secondary">
            <Trash2 size={16} />
            Clear
          </button>
          
          <div className="btn-group">
            <button onClick={exportPackets} className="btn btn-secondary" disabled={packets.length === 0}>
              <Download size={16} />
              JSON
            </button>
            <button onClick={exportPCAP} className="btn btn-secondary" disabled={packets.length === 0}>
              <Save size={16} />
              PCAP
            </button>
          </div>

          <div className="view-tabs">
            <button 
              onClick={() => { setShowStats(true); setActiveView('stats') }} 
              className={`btn ${showStats && activeView === 'stats' ? 'btn-primary' : 'btn-secondary'}`}
            >
              <BarChart3 size={16} />
              Stats
            </button>
            
            <button 
              onClick={() => { setShowStats(true); setActiveView('security') }} 
              className={`btn ${showStats && activeView === 'security' ? 'btn-primary' : 'btn-secondary'}`}
            >
              <Shield size={16} />
              Security
            </button>
            
            <button 
              onClick={() => { setShowStats(true); setActiveView('network') }} 
              className={`btn ${showStats && activeView === 'network' ? 'btn-primary' : 'btn-secondary'}`}
            >
              <Globe size={16} />
              Network
            </button>
            
            <button 
              onClick={() => { setShowStats(true); setActiveView('dissector') }} 
              className={`btn ${showStats && activeView === 'dissector' ? 'btn-primary' : 'btn-secondary'}`}
            >
              <Layers size={16} />
              Dissector
            </button>
          </div>

          <button 
            onClick={() => setShowAdvancedFilters(true)} 
            className={`btn ${advancedFilters ? 'btn-primary' : 'btn-secondary'}`}
          >
            <Sliders size={16} />
            Advanced
          </button>

          {advancedFilters && (
            <button onClick={clearAdvancedFilters} className="btn btn-danger">
              Clear Filters
            </button>
          )}
        </div>
        
        <div className="toolbar-right">
          <div className="input-group">
            <Filter size={16} />
            <input
              type="text"
              placeholder="BPF filter: tcp port 80, udp port 53, host 8.8.8.8..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              disabled={isCapturing}
              className="filter-input"
              title="BPF Examples: 'tcp port 80', 'udp port 53', 'host 192.168.1.1', 'net 192.168.0.0/24', 'icmp'"
            />
            <FilterHelper onFilterSelect={setFilter} />
          </div>
          
          <input
            type="text"
            placeholder="Search: tcp port 80, host 8.8.8.8, HTTP, SYN..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
            title="Search examples: 'tcp port 80', 'host 192.168.1.1', 'HTTP', 'SYN', 'DNS'"
          />

          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            Auto-scroll
          </label>
        </div>
      </div>

      {showAdvancedFilters && (
        <AdvancedFilters
          onApply={handleAdvancedFilters}
          onClose={() => setShowAdvancedFilters(false)}
        />
      )}

      {streamToFollow && (
        <StreamViewer
          streamId={streamToFollow}
          onClose={() => setStreamToFollow(null)}
        />
      )}

      <div className="content">
        <div className="main-content">
          {showStats && (
            <div className="sidebar-left">
              {activeView === 'stats' && (
                <>
                  <Timeline packets={packets} />
                  <PacketFlow packets={packets} />
                </>
              )}
              
              {activeView === 'security' && (
                <SecurityAnalyzer packets={packets} />
              )}
              
              {activeView === 'network' && (
                <NetworkMap packets={packets} />
              )}
              
              {activeView === 'dissector' && selectedPacket && (
                <PacketDissector packet={selectedPacket} />
              )}
              
              {activeView === 'dissector' && !selectedPacket && (
                <div className="no-packet-selected">
                  <Layers size={48} />
                  <h3>Packet Dissector</h3>
                  <p>Select a packet to view detailed dissection</p>
                </div>
              )}
            </div>
          )}

          <div className="packet-list" ref={packetListRef}>
            <div className="packet-header">
            <div className="col-time">Time</div>
            <div className="col-protocol">Protocol</div>
            <div className="col-src">Source</div>
            <div className="col-dst">Destination</div>
            <div className="col-length">Length</div>
            <div className="col-info">Info</div>
          </div>
          
          <div className="packet-rows">
            {filteredPackets.map((packet, index) => (
              <div
                key={index}
                className={`packet-row ${selectedPacket === packet ? 'selected' : ''}`}
                onClick={() => setSelectedPacket(packet)}
              >
                <div className="col-time">
                  {new Date(packet.timestamp).toLocaleTimeString('en-US', { 
                    hour12: false, 
                    hour: '2-digit', 
                    minute: '2-digit', 
                    second: '2-digit' 
                  })}.{new Date(packet.timestamp).getMilliseconds().toString().padStart(3, '0')}
                </div>
                <div className="col-protocol">
                  <span
                    className="protocol-badge"
                    style={{ backgroundColor: getProtocolColor(packet.protocol) }}
                  >
                    {packet.protocol}
                  </span>
                </div>
                <div className="col-src">{packet.src}</div>
                <div className="col-dst">{packet.dst}</div>
                <div className="col-length">{packet.length.toLocaleString()} B</div>
                <div className="col-info">{packet.info}</div>
                {packet.protocol === 'TCP' && (
                  <button
                    className="follow-stream-btn"
                    onClick={(e) => {
                      e.stopPropagation()
                      setStreamToFollow(`${packet.src}-${packet.dst}`)
                    }}
                    title="Follow TCP Stream"
                  >
                    Follow
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="packet-details">
          <h3>Packet Details</h3>
          {selectedPacket ? (
            <div className="details-content">
              <div className="detail-section">
                <h4>Frame Information</h4>
                <div className="detail-item">
                  <span className="detail-label">Timestamp:</span>
                  <span className="detail-value">
                    {new Date(selectedPacket.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Frame Length:</span>
                  <span className="detail-value">{selectedPacket.length} bytes</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Protocol Stack:</span>
                  <span className="detail-value">
                    {selectedPacket.layers?.join(' → ') || selectedPacket.protocol}
                  </span>
                </div>
              </div>

              {selectedPacket.src_mac && (
                <div className="detail-section">
                  <h4>Data Link Layer (Ethernet)</h4>
                  <div className="detail-item">
                    <span className="detail-label">Source MAC:</span>
                    <span className="detail-value">{selectedPacket.src_mac}</span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Dest MAC:</span>
                    <span className="detail-value">{selectedPacket.dst_mac}</span>
                  </div>
                </div>
              )}

              <div className="detail-section">
                <h4>Network Layer</h4>
                <div className="detail-item">
                  <span className="detail-label">Source IP:</span>
                  <span className="detail-value highlight">{selectedPacket.src}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Destination IP:</span>
                  <span className="detail-value highlight">{selectedPacket.dst}</span>
                </div>
                {selectedPacket.ttl && (
                  <div className="detail-item">
                    <span className="detail-label">TTL:</span>
                    <span className="detail-value">{selectedPacket.ttl}</span>
                  </div>
                )}
              </div>

              {(selectedPacket.protocol === 'TCP' || selectedPacket.protocol === 'UDP' || selectedPacket.protocol === 'HTTP') && (
                <div className="detail-section">
                  <h4>Transport Layer ({selectedPacket.protocol})</h4>
                  {selectedPacket.src_port && (
                    <>
                      <div className="detail-item">
                        <span className="detail-label">Source Port:</span>
                        <span className="detail-value">{selectedPacket.src_port}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Dest Port:</span>
                        <span className="detail-value">{selectedPacket.dst_port}</span>
                      </div>
                    </>
                  )}
                  {selectedPacket.tcp_flags && (
                    <div className="detail-item">
                      <span className="detail-label">TCP Flags:</span>
                      <span className="detail-value flags">{selectedPacket.tcp_flags}</span>
                    </div>
                  )}
                  {selectedPacket.seq !== undefined && (
                    <>
                      <div className="detail-item">
                        <span className="detail-label">Sequence:</span>
                        <span className="detail-value">{selectedPacket.seq}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Acknowledgment:</span>
                        <span className="detail-value">{selectedPacket.ack}</span>
                      </div>
                    </>
                  )}
                </div>
              )}

              {selectedPacket.protocol === 'HTTP' && (
                <div className="detail-section">
                  <h4>Application Layer (HTTP)</h4>
                  {selectedPacket.http_method && (
                    <div className="detail-item">
                      <span className="detail-label">Method:</span>
                      <span className="detail-value">{selectedPacket.http_method}</span>
                    </div>
                  )}
                  {selectedPacket.http_host && (
                    <div className="detail-item">
                      <span className="detail-label">Host:</span>
                      <span className="detail-value">{selectedPacket.http_host}</span>
                    </div>
                  )}
                  {selectedPacket.http_path && (
                    <div className="detail-item">
                      <span className="detail-label">Path:</span>
                      <span className="detail-value">{selectedPacket.http_path}</span>
                    </div>
                  )}
                </div>
              )}

              {selectedPacket.protocol === 'DNS' && (
                <div className="detail-section">
                  <h4>Application Layer (DNS)</h4>
                  {selectedPacket.dns_query && (
                    <div className="detail-item">
                      <span className="detail-label">Query:</span>
                      <span className="detail-value">{selectedPacket.dns_query}</span>
                    </div>
                  )}
                  {selectedPacket.dns_answers && selectedPacket.dns_answers.length > 0 && (
                    <div className="detail-item">
                      <span className="detail-label">Answers:</span>
                      <span className="detail-value">
                        {selectedPacket.dns_answers.join(', ')}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {selectedPacket.protocol === 'ICMP' && (
                <div className="detail-section">
                  <h4>ICMP</h4>
                  <div className="detail-item">
                    <span className="detail-label">Type:</span>
                    <span className="detail-value">{selectedPacket.icmp_type}</span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Code:</span>
                    <span className="detail-value">{selectedPacket.icmp_code}</span>
                  </div>
                </div>
              )}

              <div className="detail-section">
                <h4>Summary</h4>
                <div className="detail-item">
                  <span className="detail-value">{selectedPacket.info}</span>
                </div>
              </div>

              {selectedPacket.raw && (
                <div className="detail-section">
                  <h4>Hex Dump</h4>
                  <pre className="hex-dump">{formatHexDump(selectedPacket.raw)}</pre>
                </div>
              )}
            </div>
          ) : (
            <div className="no-selection">
              Select a packet to view details
            </div>
          )}
        </div>

          {showStats && activeView !== 'dissector' && (
            <Statistics packets={packets} isCapturing={isCapturing} />
          )}
          
          {showStats && activeView === 'dissector' && selectedPacket && (
            <div className="dissector-details">
              <h3>Selected Packet Details</h3>
              <div className="packet-summary">
                <div className="summary-item">
                  <span>Protocol:</span>
                  <span className="protocol-badge" style={{ backgroundColor: getProtocolColor(selectedPacket.protocol) }}>
                    {selectedPacket.protocol}
                  </span>
                </div>
                <div className="summary-item">
                  <span>Size:</span>
                  <span>{selectedPacket.length} bytes</span>
                </div>
                <div className="summary-item">
                  <span>Time:</span>
                  <span>{new Date(selectedPacket.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
