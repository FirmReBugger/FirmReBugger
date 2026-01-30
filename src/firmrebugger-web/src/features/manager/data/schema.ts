import { z } from 'zod'

export const taskStatusSchema = z.enum(['queued', 'running', 'stopping', 'completed', 'stopped', 'errored'])
export type TaskStatus = z.infer<typeof taskStatusSchema>

export const taskSchema = z.object({
  id: z.string(),
  mode: z.string(),
  benchmark: z.string(),
  fuzzer: z.string(),
  binary: z.string(),
  runs: z.number(),
  time: z.number(),
  output_dir: z.string().default(''),
  status: taskStatusSchema.default('queued'),
  progress: z.number().min(0).max(100).default(0),
  elapsedTime: z.number().default(0),
  queuePosition: z.number().optional(),
  autoQueueTriaging: z.boolean().optional().default(true), 
  triaged: z.boolean().optional().default(false), 
  createdAt: z.string().or(z.date()).transform((val) => 
    typeof val === 'string' ? new Date(val) : val
  ),
  startTime: z.string().or(z.date()).transform((val) => 
    typeof val === 'string' ? new Date(val) : val
  ),
  completedAt: z.string().or(z.date()).transform((val) => 
    typeof val === 'string' ? new Date(val) : val
  ).optional(),
})

export type Task = z.infer<typeof taskSchema>

export const createTaskSchema = z.object({
  mode: z.string().min(1, 'Mode is required'),
  fuzzer: z.string().min(1, 'Fuzzer is required'),
  binary: z.string().min(1, 'Binary is required'),
  runs: z.number().min(1, 'Runs must be at least 1'),
  time: z.number().min(1, 'Time must be at least 1 second'),
})

export type CreateTaskInput = z.infer<typeof createTaskSchema>
