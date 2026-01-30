import { useState, useEffect, useRef } from 'react'
import { Header } from '@/components/layout/header'
import { Main } from '@/components/layout/main'
import { TasksDialogs } from './components/tasks-dialogs'
import { TasksProvider } from './components/tasks-provider'
import { TasksTable } from './components/tasks-table'
import { CpuMonitor } from './components/cpu-monitor'
import { type Task } from './data/schema'
import { toast } from 'sonner'

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
            
            return {
              id: job.id,
              mode: job.mode,
              benchmark: job.benchmark || 'FirmBench',
              fuzzer: job.fuzzer,
              binary: job.binary,
              runs: job.runs,
              time: job.time,
              output_dir: job.output_dir || '',
              status: job.status || 'queued',
              progress: job.progress || 0,
              elapsedTime: job.elapsedTime || 0,
              createdAt: job.createdAt ? new Date(job.createdAt) : new Date(),
              startTime: job.startedAt ? new Date(job.startedAt) : undefined,
              completedAt: job.completedAt ? new Date(job.completedAt) : undefined,
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
    const autoQueueTriaging = async () => {
      for (const task of tasks) {
        const previousTask = previousTasksRef.current.find(t => t.id === task.id)
        
        const justCompleted = 
          previousTask?.status === 'running' &&
          task.status === 'completed'
        
        if (
          justCompleted &&
          task.mode === 'Fuzzing' &&
          task.autoQueueTriaging === true
        ) {
          const hasTriagingJob = tasks.some(t => 
            t.binary === task.binary &&
            t.fuzzer === task.fuzzer &&
            t.mode === 'Triaging' &&
            (t.status === 'running' || t.status === 'queued')
          )

          if (!hasTriagingJob) {
            try {
              const timestamp = Date.now()
              const newJobId = `JOB-${timestamp}-AUTO-TRIAGE`
              
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
              }
            } catch (error) {
              console.error('Error auto-queueing triaging:', error)
            }
          }
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
    task.status === 'completed' || task.status === 'stopped'
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
            <h3 className='text-xl font-semibold mb-3'>Active Jobs</h3>
            <TasksTable data={activeTasks} allTasks={tasks} />
          </div>
          
          {finishedTasks.length > 0 && (
            <div>
              <h3 className='text-xl font-semibold mb-3'>Finished Jobs</h3>
              <TasksTable data={finishedTasks} showCreateButton={false} enableColumnSorting={true} allTasks={tasks} />
            </div>
          )}
        </div>
      </Main>

      <TasksDialogs />
    </TasksProvider>
  )
}
