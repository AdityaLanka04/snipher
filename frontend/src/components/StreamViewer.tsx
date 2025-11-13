import { useState, useEffect } from 'react'
import { X, Copy, Download } from 'lucide-react'
import './StreamViewer.css'

interface StreamViewerProps {
  streamId: string
  onClose: () => void
}

interface StreamData {
  client_to_server: string
  server_to_client: string
  packets: number
  bytes: number
}

export default function StreamViewer({ streamId, onClose }: StreamViewerProps) {
  const [streamData, setStreamData] = useState<StreamData | null>(null)
  const [view, setView] = useState<'both' | 'client' | 'server'>('both')
  const [format, setFormat] = useState<'ascii' | 'hex'>('ascii')

  useEffect(() => {
    fetchStream()
  }, [streamId])

  const fetchStream = async () => {
    try {
      const response = await fetch(`/api/stream/${streamId}`)
      const data = await response.json()
      setStreamData(data)
    } catch (error) {
      console.error('Failed to fetch stream:', error)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const downloadStream = () => {
    if (!streamData) return
    const content = `Client → Server:\n${streamData.client_to_server}\n\nServer → Client:\n${streamData.server_to_client}`
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `stream_${streamId}.txt`
    link.click()
    URL.revokeObjectURL(url)
  }

  if (!streamData) {
    return (
      <div className="stream-overlay">
        <div className="stream-viewer">
          <div className="stream-header">
            <h3>Loading stream...</h3>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="stream-overlay">
      <div className="stream-viewer">
        <div className="stream-header">
          <h3>TCP Stream: {streamId}</h3>
          <div className="stream-controls">
            <select value={view} onChange={(e) => setView(e.target.value as any)}>
              <option value="both">Both Directions</option>
              <option value="client">Client → Server</option>
              <option value="server">Server → Client</option>
            </select>
            <select value={format} onChange={(e) => setFormat(e.target.value as any)}>
              <option value="ascii">ASCII</option>
              <option value="hex">Hex</option>
            </select>
            <button onClick={downloadStream} className="icon-btn">
              <Download size={16} />
            </button>
            <button onClick={onClose} className="icon-btn">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="stream-stats">
          <span>{streamData.packets} packets</span>
          <span>{streamData.bytes} bytes</span>
        </div>

        <div className="stream-content">
          {(view === 'both' || view === 'client') && (
            <div className="stream-direction client">
              <div className="direction-header">
                <span>Client → Server</span>
                <button onClick={() => copyToClipboard(streamData.client_to_server)}>
                  <Copy size={14} />
                </button>
              </div>
              <pre>{streamData.client_to_server || '(no data)'}</pre>
            </div>
          )}

          {(view === 'both' || view === 'server') && (
            <div className="stream-direction server">
              <div className="direction-header">
                <span>Server → Client</span>
                <button onClick={() => copyToClipboard(streamData.server_to_client)}>
                  <Copy size={14} />
                </button>
              </div>
              <pre>{streamData.server_to_client || '(no data)'}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
