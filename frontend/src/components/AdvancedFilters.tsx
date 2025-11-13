import { useState } from 'react'
import { X } from 'lucide-react'
import './AdvancedFilters.css'

interface AdvancedFiltersProps {
  onApply: (filters: FilterConfig) => void
  onClose: () => void
}

export interface FilterConfig {
  protocols: string[]
  minLength: number
  maxLength: number
  srcIp: string
  dstIp: string
  srcPort: string
  dstPort: string
  timeRange: { start: string; end: string }
}

export default function AdvancedFilters({ onApply, onClose }: AdvancedFiltersProps) {
  const [protocols, setProtocols] = useState<string[]>([])
  const [minLength, setMinLength] = useState('')
  const [maxLength, setMaxLength] = useState('')
  const [srcIp, setSrcIp] = useState('')
  const [dstIp, setDstIp] = useState('')
  const [srcPort, setSrcPort] = useState('')
  const [dstPort, setDstPort] = useState('')

  const availableProtocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ICMPv6', 'ARP', 'SSH', 'FTP', 'SMTP', 'DHCP', 'NTP', 'MySQL', 'PostgreSQL', 'Redis']

  const toggleProtocol = (protocol: string) => {
    setProtocols(prev =>
      prev.includes(protocol)
        ? prev.filter(p => p !== protocol)
        : [...prev, protocol]
    )
  }

  const handleApply = () => {
    onApply({
      protocols,
      minLength: minLength ? parseInt(minLength) : 0,
      maxLength: maxLength ? parseInt(maxLength) : Infinity,
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      timeRange: { start: '', end: '' }
    })
    onClose()
  }

  const handleReset = () => {
    setProtocols([])
    setMinLength('')
    setMaxLength('')
    setSrcIp('')
    setDstIp('')
    setSrcPort('')
    setDstPort('')
  }

  return (
    <div className="advanced-filters-overlay">
      <div className="advanced-filters">
        <div className="filters-header">
          <h3>Advanced Filters</h3>
          <button onClick={onClose} className="close-btn">
            <X size={20} />
          </button>
        </div>

        <div className="filters-content">
          <div className="filter-group">
            <label>Protocols</label>
            <div className="protocol-chips">
              {availableProtocols.map(protocol => (
                <button
                  key={protocol}
                  className={`chip ${protocols.includes(protocol) ? 'active' : ''}`}
                  onClick={() => toggleProtocol(protocol)}
                >
                  {protocol}
                </button>
              ))}
            </div>
          </div>

          <div className="filter-group">
            <label>Packet Length</label>
            <div className="range-inputs">
              <input
                type="number"
                placeholder="Min bytes"
                value={minLength}
                onChange={(e) => setMinLength(e.target.value)}
              />
              <span>to</span>
              <input
                type="number"
                placeholder="Max bytes"
                value={maxLength}
                onChange={(e) => setMaxLength(e.target.value)}
              />
            </div>
          </div>

          <div className="filter-group">
            <label>IP Addresses</label>
            <input
              type="text"
              placeholder="Source IP (e.g., 192.168.1.1)"
              value={srcIp}
              onChange={(e) => setSrcIp(e.target.value)}
            />
            <input
              type="text"
              placeholder="Destination IP"
              value={dstIp}
              onChange={(e) => setDstIp(e.target.value)}
            />
          </div>

          <div className="filter-group">
            <label>Ports</label>
            <div className="range-inputs">
              <input
                type="text"
                placeholder="Source Port"
                value={srcPort}
                onChange={(e) => setSrcPort(e.target.value)}
              />
              <input
                type="text"
                placeholder="Dest Port"
                value={dstPort}
                onChange={(e) => setDstPort(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className="filters-footer">
          <button onClick={handleReset} className="btn btn-secondary">
            Reset
          </button>
          <button onClick={handleApply} className="btn btn-primary">
            Apply Filters
          </button>
        </div>
      </div>
    </div>
  )
}
