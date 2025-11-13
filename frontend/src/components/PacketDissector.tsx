import { useState } from 'react'
import { ChevronRight, ChevronDown, Info, Shield, Clock, Zap } from 'lucide-react'
import { geoIPService } from '../utils/geoip'
import './PacketDissector.css'

interface PacketDissectorProps {
  packet: any
}

interface DissectionNode {
  name: string
  value?: string
  children?: DissectionNode[]
  expanded?: boolean
  type?: 'header' | 'field' | 'data' | 'warning' | 'error'
}

export default function PacketDissector({ packet }: PacketDissectorProps) {
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set(['frame', 'ethernet', 'ip']))

  const toggleNode = (path: string) => {
    const newExpanded = new Set(expandedNodes)
    if (newExpanded.has(path)) {
      newExpanded.delete(path)
    } else {
      newExpanded.add(path)
    }
    setExpandedNodes(newExpanded)
  }

  const buildDissectionTree = (): DissectionNode[] => {
    const tree: DissectionNode[] = []

    // Frame Information
    tree.push({
      name: 'Frame',
      children: [
        { name: 'Arrival Time', value: new Date(packet.timestamp).toLocaleString(), type: 'field' },
        { name: 'Frame Length', value: `${packet.length} bytes`, type: 'field' },
        { name: 'Capture Length', value: `${packet.length} bytes`, type: 'field' },
        { name: 'Frame Number', value: '1', type: 'field' },
        { name: 'Protocols in frame', value: packet.layers?.join(' : ') || 'Unknown', type: 'field' }
      ],
      type: 'header'
    })

    // Ethernet
    if (packet.src_mac) {
      tree.push({
        name: 'Ethernet II',
        children: [
          { name: 'Destination', value: packet.dst_mac, type: 'field' },
          { name: 'Source', value: packet.src_mac, type: 'field' },
          { name: 'Type', value: packet.layers?.includes('IPv4') ? 'IPv4 (0x0800)' : 'Unknown', type: 'field' }
        ],
        type: 'header'
      })
    }

    // IP Layer
    if (packet.layers?.includes('IPv4')) {
      const ipChildren: DissectionNode[] = [
        { name: 'Version', value: '4', type: 'field' },
        { name: 'Header Length', value: '20 bytes', type: 'field' },
        { name: 'Total Length', value: `${packet.length} bytes`, type: 'field' },
        { name: 'Identification', value: '0x1234', type: 'field' },
        { name: 'Flags', value: '0x4000 (Don\'t fragment)', type: 'field' },
        { name: 'Time to Live', value: packet.ttl?.toString() || 'Unknown', type: 'field' },
        { name: 'Protocol', value: getProtocolNumber(packet.protocol), type: 'field' },
        { name: 'Header Checksum', value: '0x0000 [validation disabled]', type: 'field' },
        { name: 'Source Address', value: packet.src.split(':')[0], type: 'field' },
        { name: 'Destination Address', value: packet.dst.split(':')[0], type: 'field' }
      ]

      // Add geolocation info
      const srcIP = packet.src.split(':')[0]
      const dstIP = packet.dst.split(':')[0]
      
      if (isPublicIP(srcIP) || isPublicIP(dstIP)) {
        const geoChildren: DissectionNode[] = []
        
        if (isPublicIP(srcIP)) {
          geoChildren.push({ name: 'Source Country', value: getCountryFromIP(srcIP), type: 'field' })
        }
        
        if (isPublicIP(dstIP)) {
          geoChildren.push({ name: 'Destination Country', value: getCountryFromIP(dstIP), type: 'field' })
        }
        
        if (geoChildren.length > 0) {
          ipChildren.push({
            name: 'GeoIP Info',
            children: geoChildren,
            type: 'header'
          })
        }
      }

      tree.push({
        name: 'Internet Protocol Version 4',
        children: ipChildren,
        type: 'header'
      })
    }

    // TCP Layer
    if (packet.protocol === 'TCP' || packet.tcp_flags) {
      const tcpChildren: DissectionNode[] = [
        { name: 'Source Port', value: packet.src_port?.toString() || 'Unknown', type: 'field' },
        { name: 'Destination Port', value: packet.dst_port?.toString() || 'Unknown', type: 'field' },
        { name: 'Sequence Number', value: packet.seq?.toString() || 'Unknown', type: 'field' },
        { name: 'Acknowledgment Number', value: packet.ack?.toString() || 'Unknown', type: 'field' },
        { name: 'Header Length', value: '20 bytes', type: 'field' },
        { name: 'Flags', value: `0x${getFlagHex(packet.tcp_flags)} (${packet.tcp_flags || 'None'})`, type: 'field' },
        { name: 'Window Size', value: '65535', type: 'field' },
        { name: 'Checksum', value: '0x0000 [validation disabled]', type: 'field' }
      ]

      // Add TCP analysis
      if (packet.tcp_flags) {
        const analysis = analyzeTCPFlags(packet.tcp_flags)
        if (analysis.length > 0) {
          tcpChildren.push({
            name: 'TCP Analysis',
            children: analysis.map(item => ({ name: item.name, value: item.value, type: item.type as any })),
            type: 'header'
          })
        }
      }

      tree.push({
        name: 'Transmission Control Protocol',
        children: tcpChildren,
        type: 'header'
      })
    }

    // Application Layer
    if (packet.protocol === 'HTTP' && packet.raw) {
      const httpData = parseHTTPData(packet.raw)
      if (httpData) {
        tree.push({
          name: 'Hypertext Transfer Protocol',
          children: httpData,
          type: 'header'
        })
      }
    }

    // Security Analysis
    const securityIssues = analyzePacketSecurity(packet)
    if (securityIssues.length > 0) {
      tree.push({
        name: 'Security Analysis',
        children: securityIssues.map(issue => ({ 
          name: issue.name, 
          value: issue.description, 
          type: issue.severity as any 
        })),
        type: 'warning'
      })
    }

    return tree
  }

  const renderNode = (node: DissectionNode, path: string, depth: number = 0) => {
    const isExpanded = expandedNodes.has(path)
    const hasChildren = node.children && node.children.length > 0

    return (
      <div key={path} className={`dissection-node depth-${depth}`}>
        <div 
          className={`node-header ${node.type || 'field'}`}
          onClick={() => hasChildren && toggleNode(path)}
        >
          <div className="node-expand">
            {hasChildren && (
              isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />
            )}
          </div>
          <div className="node-content">
            <span className="node-name">{node.name}</span>
            {node.value && <span className="node-value">: {node.value}</span>}
          </div>
          {node.type === 'warning' && <Shield size={14} className="warning-icon" />}
          {node.type === 'error' && <Zap size={14} className="error-icon" />}
        </div>
        
        {hasChildren && isExpanded && (
          <div className="node-children">
            {node.children!.map((child, index) => 
              renderNode(child, `${path}.${index}`, depth + 1)
            )}
          </div>
        )}
      </div>
    )
  }

  const dissectionTree = buildDissectionTree()

  return (
    <div className="packet-dissector">
      <div className="dissector-header">
        <Info size={16} />
        <h3>Packet Dissection</h3>
      </div>
      <div className="dissection-tree">
        {dissectionTree.map((node, index) => 
          renderNode(node, index.toString(), 0)
        )}
      </div>
    </div>
  )
}

// Helper functions
function getProtocolNumber(protocol: string): string {
  const protocolMap: Record<string, string> = {
    'TCP': '6 (TCP)',
    'UDP': '17 (UDP)',
    'ICMP': '1 (ICMP)',
    'HTTP': '6 (TCP)',
    'HTTPS': '6 (TCP)'
  }
  return protocolMap[protocol] || 'Unknown'
}

function getFlagHex(flags: string): string {
  if (!flags) return '00'
  let value = 0
  if (flags.includes('SYN')) value |= 0x02
  if (flags.includes('ACK')) value |= 0x10
  if (flags.includes('FIN')) value |= 0x01
  if (flags.includes('RST')) value |= 0x04
  if (flags.includes('PSH')) value |= 0x08
  if (flags.includes('URG')) value |= 0x20
  return value.toString(16).padStart(2, '0')
}

function analyzeTCPFlags(flags: string): Array<{name: string, value: string, type: string}> {
  const analysis = []
  
  if (flags.includes('SYN') && !flags.includes('ACK')) {
    analysis.push({ name: 'Connection', value: 'Connection establishment (SYN)', type: 'field' })
  } else if (flags.includes('SYN') && flags.includes('ACK')) {
    analysis.push({ name: 'Connection', value: 'Connection establishment (SYN-ACK)', type: 'field' })
  } else if (flags.includes('FIN')) {
    analysis.push({ name: 'Connection', value: 'Connection termination (FIN)', type: 'field' })
  } else if (flags.includes('RST')) {
    analysis.push({ name: 'Connection', value: 'Connection reset (RST)', type: 'warning' })
  }
  
  if (flags.includes('PSH')) {
    analysis.push({ name: 'Data', value: 'Push flag set - immediate delivery', type: 'field' })
  }
  
  return analysis
}

function parseHTTPData(rawHex: string): DissectionNode[] | null {
  try {
    const bytes = rawHex.split(' ').map(h => parseInt(h, 16))
    const text = String.fromCharCode(...bytes)
    const lines = text.split('\r\n')
    
    if (lines.length > 0) {
      const children: DissectionNode[] = []
      
      // Request/Response line
      children.push({ name: 'Request Line', value: lines[0], type: 'field' })
      
      // Headers
      for (let i = 1; i < lines.length && lines[i]; i++) {
        const [key, ...valueParts] = lines[i].split(': ')
        if (valueParts.length > 0) {
          children.push({ name: key, value: valueParts.join(': '), type: 'field' })
        }
      }
      
      return children
    }
  } catch (e) {
    // Ignore parsing errors
  }
  return null
}

function isPublicIP(ip: string): boolean {
  return geoIPService.isPublicIP(ip)
}

// Use the centralized GeoIP service
function getCountryFromIP(ip: string): string {
  return geoIPService.getCountry(ip)
}

function analyzePacketSecurity(packet: any): Array<{name: string, description: string, severity: string}> {
  const issues = []
  
  // Unencrypted protocols
  if (packet.protocol === 'HTTP') {
    issues.push({
      name: 'Unencrypted Traffic',
      description: 'HTTP traffic is not encrypted and can be intercepted',
      severity: 'warning'
    })
  }
  
  if (packet.protocol === 'Telnet') {
    issues.push({
      name: 'Insecure Protocol',
      description: 'Telnet sends credentials in plain text',
      severity: 'error'
    })
  }
  
  if (packet.protocol === 'FTP' && packet.dst_port === 21) {
    issues.push({
      name: 'Insecure File Transfer',
      description: 'FTP control channel is unencrypted',
      severity: 'warning'
    })
  }
  
  // Suspicious ports
  const suspiciousPorts = [1337, 31337, 4444, 5555, 6666, 7777]
  if (packet.dst_port && suspiciousPorts.includes(packet.dst_port)) {
    issues.push({
      name: 'Suspicious Port',
      description: `Port ${packet.dst_port} is commonly used by malware`,
      severity: 'error'
    })
  }
  
  return issues
}