import { useState, useEffect, useRef } from 'react'
import { Header } from '@/components/layout/header'
import { Main } from '@/components/layout/main'
import { TasksDialogs } from './components/tasks-dialogs'
import { TasksProvider } from './components/tasks-provider'
import { TasksTable } from './components/tasks-table'
import { CpuMonitor } from './components/cpu-monitor'
import { type Task } from './data/schema'
import { toast } from 'sonner'
import { FileCheck, CircleAlert, LoaderCircle } from 'lucide-react'

function toDateOrUndefined(value: unknown): Date | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? undefined : value
  }

  if (typeof value === 'number') {
    const numericValue = Number.isFinite(value) ? value : NaN
    if (Number.isNaN(numericValue)) return undefined
    const milliseconds = Math.abs(numericValue) < 1e11 ? numericValue * 1000 : numericValue
    const date = new Date(milliseconds)
    return Number.isNaN(date.getTime()) ? undefined : date
  }

  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed) return undefined

    const asNumber = Number(trimmed)
    if (!Number.isNaN(asNumber)) {
      const milliseconds = Math.abs(asNumber) < 1e11 ? asNumber * 1000 : asNumber
      const dateFromNumber = new Date(milliseconds)
      if (!Number.isNaN(dateFromNumber.getTime())) {
        return dateFromNumber
      }
    }

    const dateFromString = new Date(trimmed)
    return Number.isNaN(dateFromString.getTime()) ? undefined : dateFromString
  }

  return undefined
}

export function Manager() {
  const [tasks, setTasks] = useState<Task[]>([])
  const previousTasksRef = useRef<Task[]>([])
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

  const fetchJobs = async () => {
    try {
      const response = await fetch(`${API_URL}/api/jobs/list`)
      const data = await response.json()
      
      if (data.jobs) {
        setTasks(prevTasks => {
          const formattedTasks: Task[] = data.jobs.map((job: any, index: number) => {
            const existingTask = prevTasks.find(t => t.id === job.id)
            const normalizedStatus = job.status === 'error' ? 'errored' : job.status
            
            return {
              id: job.id,
              mode: job.mode,
              benchmark: job.benchmark || 'FirmBench',
              fuzzer: job.fuzzer,
              binary: job.binary,
              runs: job.runs,
              time: job.time,
              output_dir: job.output_dir || '',
              status: normalizedStatus || 'queued',
              progress: job.progress || 0,
              elapsedTime: job.elapsedTime || 0,
              createdAt: toDateOrUndefined(job.createdAt) ?? new Date(),
              startTime: toDateOrUndefined(job.startedAt),
              completedAt: toDateOrUndefined(job.completedAt),
              queuePosition: index,
              autoQueueTriaging: existingTask?.autoQueueTriaging ?? job.autoQueueTriaging ?? true,
              triaged: job.triaged ?? false,
            }
          })
          return formattedTasks
        })
      } else {
        console.log('No jobs in response')
      }
    } catch (error) {
      console.error('Failed to fetch jobs:', error)
    }
  }

  useEffect(() => {
    fetchJobs()
    
    const pollInterval = setInterval(fetchJobs, 2000)
    
    return () => clearInterval(pollInterval)
  }, [])

  useEffect(() => {
    const previousTasksSnapshot = previousTasksRef.current
    const tasksToAutoQueue = tasks.filter((task) => {
      const previousTask = previousTasksSnapshot.find((t) => t.id === task.id)

      const justCompleted =
        !!previousTask &&
        previousTask.status !== 'completed' &&
        task.status === 'completed'

      if (
        !justCompleted ||
        task.mode !== 'Fuzzing' ||
        task.autoQueueTriaging !== true ||
        task.triaged === true
      ) {
        return false
      }

      const hasTriagingJob = tasks.some((t) =>
        t.benchmark === task.benchmark &&
        t.binary === task.binary &&
        t.fuzzer === task.fuzzer &&
        t.output_dir === task.output_dir &&
        t.mode === 'Triaging' &&
        (t.status === 'running' || t.status === 'queued')
      )

      return !hasTriagingJob
    })

    const autoQueueTriaging = async () => {
      for (const task of tasksToAutoQueue) {
        try {
          const timestamp = Date.now()
          const newJobId = `JOB-${timestamp}-${task.id}-AUTO-TRIAGE`

          const triagingJobData = {
            job_id: newJobId,
            fuzzer: task.fuzzer,
            benchmark: task.benchmark,
            duration: task.time,
            binary: task.binary,
            runs: task.runs,
            mode: 'Triaging',
            output_dir: task.output_dir,
          }

          const response = await fetch(`${API_URL}/api/jobs/add`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              jobs: [triagingJobData]
            }),
          })

          if (response.ok) {
            toast.success(`Auto-queued triaging for ${task.binary}`)
          } else {
            const responseData = await response.json().catch(() => ({}))
            console.error('Auto-queue triaging failed:', {
              jobId: task.id,
              binary: task.binary,
              fuzzer: task.fuzzer,
              outputDir: task.output_dir,
              error: responseData?.error,
            })
          }
        } catch (error) {
          console.error('Error auto-queueing triaging:', error)
        }
      }
    }

    autoQueueTriaging()
    
    previousTasksRef.current = tasks
  }, [tasks])

  const activeTasks = tasks.filter(task => 
    task.status === 'running' || task.status === 'queued'
  )
  const finishedTasks = tasks.filter(task => 
    task.mode !== 'Triaging' &&
    (task.status === 'completed' || task.status === 'stopped' || task.status === 'errored')
  )

  return (
    <TasksProvider tasks={tasks} setTasks={setTasks}>
      <Header fixed />

      <Main className='flex flex-1 flex-col gap-4 sm:gap-6'>
        <div className='flex flex-wrap items-end justify-between gap-2'>
          <div>
            <h2 className='text-2xl font-bold tracking-tight'>Job Scheduler</h2>
            <p className='text-muted-foreground'>
              Schedule fuzzing and triaging jobs. 
            </p>
          </div>
        </div>
        
        <CpuMonitor />
        
        <div className='flex flex-col gap-6'>
          <div>
            <div className='mb-3 flex flex-wrap items-center justify-between gap-2'>
              <h3 className='text-xl font-semibold'>Active Jobs</h3>
              <div className='flex flex-wrap items-center gap-3 text-xs text-muted-foreground'>
                <div className='flex items-center gap-1.5'>
                  <FileCheck className='h-3.5 w-3.5 text-blue-500' />
                  <span>Triaged</span>
                </div>
                <div className='flex items-center gap-1.5'>
                  <CircleAlert className='h-3.5 w-3.5 text-red-500' />
                  <span>Triaging failed</span>
                </div>
                <div className='flex items-center gap-1.5'>
                  <LoaderCircle className='h-3.5 w-3.5 text-amber-500' />
                  <span>Triaging in progress</span>
                </div>
              </div>
            </div>
            <TasksTable data={activeTasks} allTasks={tasks} />
          </div>
          
          {finishedTasks.length > 0 && (
            <div>
              <h3 className='text-xl font-semibold mb-3'>Finished Jobs</h3>
              <TasksTable data={finishedTasks} showCreateButton={false} enableColumnSorting={true} allTasks={tasks} isFinishedJobs={true} />
            </div>
          )}
        </div>
      </Main>

      <TasksDialogs />
    </TasksProvider>
  )
}
