import { useMemo } from 'react'
import { Shield, AlertTriangle, Eye, Lock, Unlock, Zap } from 'lucide-react'
import './SecurityAnalyzer.css'

interface SecurityAnalyzerProps {
  packets: any[]
}

interface SecurityThreat {
  id: string
  type: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  packets: number
  recommendation: string
  icon: React.ReactNode
}

export default function SecurityAnalyzer({ packets }: SecurityAnalyzerProps) {
  const securityAnalysis = useMemo(() => {
    const threats: SecurityThreat[] = []
    const stats = {
      unencrypted: 0,
      encrypted: 0,
      suspicious: 0,
      total: packets.length
    }

    // Analyze packets for security issues
    const suspiciousPorts = new Set<number>()
    const unencryptedProtocols = new Set<string>()
    const encryptedProtocols = new Set<string>()
    const dnsQueries = new Set<string>()
    const httpHosts = new Set<string>()

    packets.forEach(packet => {
      // Track encryption status
      if (['HTTP', 'FTP', 'Telnet', 'SMTP'].includes(packet.protocol)) {
        stats.unencrypted++
        unencryptedProtocols.add(packet.protocol)
      } else if (['HTTPS', 'SSH', 'FTPS', 'SMTPS', 'TLS'].includes(packet.protocol)) {
        stats.encrypted++
        encryptedProtocols.add(packet.protocol)
      }

      // Check for suspicious ports
      const suspiciousPortList = [1337, 31337, 4444, 5555, 6666, 7777, 8080, 9999]
      if (packet.dst_port && suspiciousPortList.includes(packet.dst_port)) {
        suspiciousPorts.add(packet.dst_port)
        stats.suspicious++
      }

      // Collect DNS queries
      if (packet.protocol === 'DNS' && packet.dns_query) {
        dnsQueries.add(packet.dns_query)
      }

      // Collect HTTP hosts
      if (packet.protocol === 'HTTP' && packet.http_host) {
        httpHosts.add(packet.http_host)
      }
    })

    // Generate threat assessments
    if (stats.unencrypted > 0) {
      threats.push({
        id: 'unencrypted-traffic',
        type: unencryptedProtocols.has('HTTP') ? 'high' : 'medium',
        title: 'Unencrypted Traffic Detected',
        description: `${stats.unencrypted} packets using unencrypted protocols: ${Array.from(unencryptedProtocols).join(', ')}`,
        packets: stats.unencrypted,
        recommendation: 'Use HTTPS, SSH, and other encrypted protocols when possible',
        icon: <Unlock size={16} />
      })
    }

    if (suspiciousPorts.size > 0) {
      threats.push({
        id: 'suspicious-ports',
        type: 'critical',
        title: 'Suspicious Port Activity',
        description: `Traffic detected on commonly malicious ports: ${Array.from(suspiciousPorts).join(', ')}`,
        packets: stats.suspicious,
        recommendation: 'Investigate these connections immediately. Block if unauthorized.',
        icon: <AlertTriangle size={16} />
      })
    }

    if (unencryptedProtocols.has('Telnet')) {
      threats.push({
        id: 'telnet-usage',
        type: 'critical',
        title: 'Telnet Protocol Detected',
        description: 'Telnet sends credentials and data in plain text',
        packets: packets.filter(p => p.protocol === 'Telnet').length,
        recommendation: 'Replace Telnet with SSH immediately',
        icon: <Eye size={16} />
      })
    }

    if (httpHosts.size > 0) {
      threats.push({
        id: 'http-hosts',
        type: 'medium',
        title: 'HTTP Websites Accessed',
        description: `Unencrypted web traffic to: ${Array.from(httpHosts).slice(0, 3).join(', ')}${httpHosts.size > 3 ? '...' : ''}`,
        packets: packets.filter(p => p.protocol === 'HTTP').length,
        recommendation: 'Use HTTPS versions of these websites',
        icon: <Unlock size={16} />
      })
    }

    // Check for DNS over HTTP (DoH) or DNS over TLS (DoT)
    const dnsOverHttps = packets.filter(p => 
      p.protocol === 'HTTPS' && (p.dst_port === 853 || p.info?.includes('dns'))
    )
    if (dnsOverHttps.length > 0) {
      threats.push({
        id: 'secure-dns',
        type: 'info',
        title: 'Secure DNS Detected',
        description: 'DNS over HTTPS/TLS is being used',
        packets: dnsOverHttps.length,
        recommendation: 'Good! Continue using secure DNS',
        icon: <Lock size={16} />
      })
    }

    // Check for potential data exfiltration (large uploads)
    const largeUploads = packets.filter(p => 
      p.length > 1000 && p.protocol === 'HTTP'
    )
    if (largeUploads.length > 10) {
      threats.push({
        id: 'large-uploads',
        type: 'medium',
        title: 'Large HTTP Uploads Detected',
        description: `${largeUploads.length} large HTTP uploads detected`,
        packets: largeUploads.length,
        recommendation: 'Monitor for potential data exfiltration',
        icon: <Zap size={16} />
      })
    }

    return { threats, stats }
  }, [packets])

  const getThreatColor = (type: string) => {
    switch (type) {
      case 'critical': return '#ff4a4a'
      case 'high': return '#ff6a4a'
      case 'medium': return '#ffa94a'
      case 'low': return '#ffff4a'
      case 'info': return '#4aff88'
      default: return '#888'
    }
  }

  const getSecurityScore = () => {
    const { stats } = securityAnalysis
    if (stats.total === 0) return 100
    
    const encryptedRatio = stats.encrypted / stats.total
    const unencryptedPenalty = (stats.unencrypted / stats.total) * 30
    const suspiciousPenalty = (stats.suspicious / stats.total) * 50
    
    const score = Math.max(0, 100 - unencryptedPenalty - suspiciousPenalty + (encryptedRatio * 20))
    return Math.round(score)
  }

  const securityScore = getSecurityScore()

  return (
    <div className="security-analyzer">
      <div className="security-header">
        <Shield size={16} />
        <h3>Security Analysis</h3>
        <div className={`security-score ${securityScore >= 80 ? 'good' : securityScore >= 60 ? 'medium' : 'poor'}`}>
          {securityScore}/100
        </div>
      </div>

      <div className="security-overview">
        <div className="security-stat">
          <Lock size={14} />
          <span>Encrypted: {securityAnalysis.stats.encrypted}</span>
        </div>
        <div className="security-stat">
          <Unlock size={14} />
          <span>Unencrypted: {securityAnalysis.stats.unencrypted}</span>
        </div>
        <div className="security-stat">
          <AlertTriangle size={14} />
          <span>Suspicious: {securityAnalysis.stats.suspicious}</span>
        </div>
      </div>

      <div className="threats-list">
        {securityAnalysis.threats.length === 0 ? (
          <div className="no-threats">
            <Shield size={24} />
            <span>No security threats detected</span>
          </div>
        ) : (
          securityAnalysis.threats.map(threat => (
            <div key={threat.id} className={`threat-item ${threat.type}`}>
              <div className="threat-header">
                <div className="threat-icon" style={{ color: getThreatColor(threat.type) }}>
                  {threat.icon}
                </div>
                <div className="threat-title">
                  <span>{threat.title}</span>
                  <span className="threat-type">{threat.type.toUpperCase()}</span>
                </div>
                <div className="threat-count">{threat.packets}</div>
              </div>
              
              <div className="threat-description">
                {threat.description}
              </div>
              
              <div className="threat-recommendation">
                <strong>Recommendation:</strong> {threat.recommendation}
              </div>
            </div>
          ))
        )}
      </div>

      <div className="security-tips">
        <h4>Security Best Practices</h4>
        <ul>
          <li>Always use HTTPS instead of HTTP</li>
          <li>Avoid Telnet, use SSH instead</li>
          <li>Monitor unusual port activity</li>
          <li>Use VPN for sensitive communications</li>
          <li>Enable DNS over HTTPS (DoH)</li>
          <li>Regularly update security software</li>
        </ul>
      </div>
    </div>
  )
}