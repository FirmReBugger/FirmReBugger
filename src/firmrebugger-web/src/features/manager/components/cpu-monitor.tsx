import { useEffect, useState } from 'react'
import { Card, CardHeader } from '@/components/ui/card'
import { Cpu } from 'lucide-react'
import { cn } from '@/lib/utils'

export function CpuMonitor() {
  const [cpuUsage, setCpuUsage] = useState<number[]>([])
  const [coreCount, setCoreCount] = useState(0)
  const API_URL = import.meta.env.VITE_API_URL || ''

  useEffect(() => {
    const fetchCpuUsage = async () => {
      try {
        const response = await fetch(`${API_URL}/api/system/cpu`)
        const data = await response.json()
        
        if (data.cpu_usage) {
          setCpuUsage(data.cpu_usage)
          setCoreCount(data.core_count)
        }
      } catch (error) {
        console.error('Failed to fetch CPU usage:', error)
      }
    }

    fetchCpuUsage()

    let fallbackInterval: ReturnType<typeof setInterval> | null = null
    const eventSource = new EventSource(`${API_URL}/api/system/cpu/stream`)

    const ensureFallbackPolling = () => {
      if (fallbackInterval) return
      fallbackInterval = setInterval(fetchCpuUsage, 5000)
    }

    eventSource.addEventListener('cpu', (event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data)
        if (payload.cpu_usage) {
          setCpuUsage(payload.cpu_usage)
          setCoreCount(payload.core_count || payload.cpu_usage.length)
        }
      } catch (error) {
        console.error('Failed to parse CPU stream payload:', error)
      }
    })

    eventSource.onerror = (error) => {
      console.error('CPU stream disconnected, enabling fallback polling:', error)
      ensureFallbackPolling()
    }

    return () => {
      eventSource.close()
      if (fallbackInterval) {
        clearInterval(fallbackInterval)
      }
    }
  }, [])

  const getUsageColor = (usage: number) => {
    if (usage > 80) return 'bg-red-500'
    if (usage > 50) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  const averageUsage = cpuUsage.length > 0 
    ? cpuUsage.reduce((a, b) => a + b, 0) / cpuUsage.length
    : 0

  const benchmarkCores = Math.max(1, coreCount - 2)

  return (
    <Card className=''>
      <CardHeader className='py-2 px-4'>
        <div className='flex items-center gap-4'>
          <div className='flex items-center gap-2 min-w-fit'>
            <Cpu className='h-3 w-3' />
            <span className='text-xs font-medium'>System CPU</span>
            <span className='text-xs text-muted-foreground'>({coreCount} cores)</span>
          </div>
          
          <div className='flex-1 flex items-center gap-2'>
            <div className='flex-1 h-4 bg-muted rounded-sm overflow-hidden'>
              <div
                className={cn(
                  'h-full transition-all duration-300',
                  getUsageColor(averageUsage)
                )}
                style={{ width: `${averageUsage}%` }}
              />
            </div>
            <span className='text-xs font-mono font-semibold min-w-[3ch]'>{averageUsage.toFixed(1)}%</span>
          </div>
          
          <div className='text-[10px] text-muted-foreground'>
            Benchmark: {benchmarkCores} cores
          </div>
        </div>
      </CardHeader>
    </Card>
  )
}
