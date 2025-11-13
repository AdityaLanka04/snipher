import { useState } from 'react'
import { HelpCircle, X, Copy } from 'lucide-react'
import './FilterHelper.css'

interface FilterHelperProps {
  onFilterSelect: (filter: string) => void
}

export default function FilterHelper({ onFilterSelect }: FilterHelperProps) {
  const [isOpen, setIsOpen] = useState(false)

  const filterExamples = [
    {
      category: 'Protocol Filters',
      filters: [
        { filter: 'tcp', description: 'All TCP traffic' },
        { filter: 'udp', description: 'All UDP traffic' },
        { filter: 'icmp', description: 'All ICMP traffic (ping)' },
        { filter: 'arp', description: 'Address Resolution Protocol' }
      ]
    },
    {
      category: 'Port Filters',
      filters: [
        { filter: 'tcp port 80', description: 'HTTP traffic' },
        { filter: 'tcp port 443', description: 'HTTPS traffic' },
        { filter: 'udp port 53', description: 'DNS queries' },
        { filter: 'tcp port 22', description: 'SSH connections' },
        { filter: 'tcp port 21', description: 'FTP traffic' },
        { filter: 'tcp port 25', description: 'SMTP email' }
      ]
    },
    {
      category: 'Host Filters',
      filters: [
        { filter: 'host 8.8.8.8', description: 'Traffic to/from Google DNS' },
        { filter: 'host 192.168.1.1', description: 'Traffic to/from router' },
        { filter: 'src host 192.168.1.100', description: 'Traffic from specific IP' },
        { filter: 'dst host 8.8.8.8', description: 'Traffic to specific IP' }
      ]
    },
    {
      category: 'Network Filters',
      filters: [
        { filter: 'net 192.168.0.0/24', description: 'Local network traffic' },
        { filter: 'net 10.0.0.0/8', description: 'Private network 10.x.x.x' },
        { filter: 'not net 192.168.0.0/16', description: 'Exclude local traffic' }
      ]
    },
    {
      category: 'Combined Filters',
      filters: [
        { filter: 'tcp port 80 or tcp port 443', description: 'HTTP and HTTPS' },
        { filter: 'host 8.8.8.8 and udp', description: 'UDP traffic to Google DNS' },
        { filter: 'tcp and not port 22', description: 'TCP traffic except SSH' },
        { filter: 'port 53 or port 80', description: 'DNS or HTTP traffic' }
      ]
    }
  ]

  const copyFilter = (filter: string) => {
    navigator.clipboard.writeText(filter)
    onFilterSelect(filter)
    setIsOpen(false)
  }

  return (
    <div className="filter-helper">
      <button 
        className="help-button"
        onClick={() => setIsOpen(!isOpen)}
        title="BPF Filter Help"
      >
        <HelpCircle size={16} />
      </button>

      {isOpen && (
        <div className="filter-overlay">
          <div className="filter-popup">
            <div className="popup-header">
              <h3>BPF Filter Examples</h3>
              <button onClick={() => setIsOpen(false)} className="close-button">
                <X size={16} />
              </button>
            </div>

            <div className="popup-content">
              <div className="filter-info">
                <p>Berkeley Packet Filter (BPF) syntax allows precise packet filtering at capture time.</p>
                <p><strong>Click any example to use it:</strong></p>
              </div>

              {filterExamples.map((category, idx) => (
                <div key={idx} className="filter-category">
                  <h4>{category.category}</h4>
                  <div className="filter-list">
                    {category.filters.map((item, filterIdx) => (
                      <div 
                        key={filterIdx} 
                        className="filter-item"
                        onClick={() => copyFilter(item.filter)}
                      >
                        <div className="filter-code">
                          <code>{item.filter}</code>
                          <Copy size={12} className="copy-icon" />
                        </div>
                        <div className="filter-desc">{item.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              <div className="filter-tips">
                <h4>Tips:</h4>
                <ul>
                  <li>Use <code>and</code>, <code>or</code>, <code>not</code> to combine filters</li>
                  <li>Use parentheses for complex expressions: <code>(tcp port 80) or (udp port 53)</code></li>
                  <li>BPF filters are applied at capture time for better performance</li>
                  <li>Use the search bar for post-capture filtering</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}