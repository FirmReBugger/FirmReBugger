import { useEffect, useState, useRef } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Copy, Download, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'

interface TaskLogsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  taskId: string | null
  runNumber: number | null
  title?: string | null
  downloadFilename?: string | null
  logUrl?: string | null
}

export function TaskLogsDialog({
  open,
  onOpenChange,
  taskId,
  runNumber,
  title,
  downloadFilename,
  logUrl,
}: TaskLogsDialogProps) {
  const [logs, setLogs] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [logPath, setLogPath] = useState<string>('')
  const scrollAreaRef = useRef<HTMLDivElement>(null)
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

  const fetchLogs = async () => {
    if (!taskId && !logUrl) return

    setLoading(true)
    setError(null)

    try {
      const response = await fetch(
        logUrl || `${API_URL}/api/tasks/logs?task_id=${taskId}`
      )
      const data = await response.json()

      if (response.ok) {
        setLogs(data.content || '')
        setLogPath(data.path || '')
      } else {
        setError(data.error || 'Failed to load logs')
        setLogs('')
      }
    } catch (err) {
      setError('Failed to fetch logs')
      console.error('Error fetching logs:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (open && (taskId || logUrl)) {
      fetchLogs()
    }
  }, [open, taskId, logUrl])

  useEffect(() => {
    if (logs && scrollAreaRef.current) {
      const scrollContainer = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]')
      if (scrollContainer) {
        scrollContainer.scrollTop = scrollContainer.scrollHeight
      }
    }
  }, [logs])

  const handleCopy = () => {
    navigator.clipboard.writeText(logs)
    toast.success('Logs copied to clipboard')
  }

  const handleDownload = () => {
    const blob = new Blob([logs], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = downloadFilename || (runNumber !== null ? `log-${runNumber}.log` : 'log.txt')
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    toast.success('Log file downloaded')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className='!w-[95vw] !max-w-[1400px] h-[85vh] flex flex-col'>
        <DialogHeader>
          <DialogTitle className='flex items-center gap-2'>
            {title || (runNumber !== null ? `Task Logs - Run #${runNumber}` : 'Task Logs')}
          </DialogTitle>
          <DialogDescription className='font-mono text-xs'>
            {logPath}
          </DialogDescription>
        </DialogHeader>

        <div className='flex gap-2 pb-2'>
          <Button
            variant='outline'
            size='sm'
            onClick={fetchLogs}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button
            variant='outline'
            size='sm'
            onClick={handleCopy}
            disabled={!logs || loading}
          >
            <Copy className='h-4 w-4 mr-2' />
            Copy
          </Button>
          <Button
            variant='outline'
            size='sm'
            onClick={handleDownload}
            disabled={!logs || loading}
          >
            <Download className='h-4 w-4 mr-2' />
            Download
          </Button>
        </div>

        <div className='flex-1 min-h-0'>
          {loading ? (
            <div className='flex items-center justify-center h-full text-muted-foreground'>
              <div className='flex items-center gap-2'>
                <div className='animate-spin rounded-full h-5 w-5 border-b-2 border-primary'></div>
                <span>Loading logs...</span>
              </div>
            </div>
          ) : error ? (
            <div className='flex items-center justify-center h-full text-destructive'>
              <div className='text-center space-y-2'>
                <p className='font-semibold'>Error Loading Logs</p>
                <p className='text-sm'>{error}</p>
              </div>
            </div>
          ) : logs ? (
            <ScrollArea ref={scrollAreaRef} className='h-full rounded-md border bg-muted/30'>
              <pre className='p-4 text-xs font-mono whitespace-pre-wrap break-words'>
                {logs}
              </pre>
            </ScrollArea>
          ) : (
            <div className='flex items-center justify-center h-full text-muted-foreground'>
              <p>No logs available</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
