import { type Table } from '@tanstack/react-table'
import { Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { DataTableBulkActions as BulkActionsToolbar } from '@/components/data-table'
import { type Task } from '../data/schema'
import { useTasks } from './tasks-provider'

type DataTableBulkActionsProps<TData> = {
  table: Table<TData>
}

export function DataTableBulkActions<TData>({
  table,
}: DataTableBulkActionsProps<TData>) {
  const { setTasks } = useTasks()

  const handleDelete = () => {
    const selectedRows = table.getFilteredSelectedRowModel().rows
    const selectedTaskIds = selectedRows.map((row) => (row.original as Task).id)
    const count = selectedRows.length

    // Delete immediately
    setTasks((prevTasks) => 
      prevTasks.filter((task) => !selectedTaskIds.includes(task.id))
    )
    
    table.resetRowSelection()
    
    toast.success(`Deleted ${count} ${count > 1 ? 'tasks' : 'task'}`)
  }

  return (
    <BulkActionsToolbar table={table} entityName='task'>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant='destructive'
            size='icon'
            onClick={handleDelete}
            className='size-8'
            aria-label='Delete selected tasks'
            title='Delete selected tasks'
          >
            <Trash2 />
            <span className='sr-only'>Delete selected tasks</span>
          </Button>
        </TooltipTrigger>
        <TooltipContent>
          <p>Delete selected tasks</p>
        </TooltipContent>
      </Tooltip>
    </BulkActionsToolbar>
  )
}
