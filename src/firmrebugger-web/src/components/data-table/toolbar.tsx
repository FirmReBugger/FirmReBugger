import { Cross2Icon } from '@radix-ui/react-icons'
import { type Table } from '@tanstack/react-table'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { DataTableFacetedFilter } from './faceted-filter'

type DataTableToolbarProps<TData> = {
  table: Table<TData>
  searchPlaceholder?: string
  searchKey?: string
  filters?: {
    columnId: string
    title: string
    options: {
      label: string
      value: string
      icon?: React.ComponentType<{ className?: string }>
    }[]
  }[]
  createButton?: React.ReactNode
}

export function DataTableToolbar<TData>({
  table,
  searchPlaceholder = 'Filter...',
  searchKey,
  filters = [],
  createButton,
}: DataTableToolbarProps<TData>) {
  const isFiltered =
    table.getState().columnFilters.length > 0 || table.getState().globalFilter

  return (
    <div className='flex items-center justify-between'>
      <div className='flex flex-1 flex-col-reverse items-start gap-y-2 sm:flex-row sm:items-center sm:space-x-2'>
        <div className='relative'>
          {searchKey ? (
            <Input
              placeholder={searchPlaceholder}
              value={
                (table.getColumn(searchKey)?.getFilterValue() as string) ?? ''
              }
              onChange={(event) =>
                table.getColumn(searchKey)?.setFilterValue(event.target.value)
              }
              className='h-8 w-[150px] pr-8 lg:w-[250px]'
            />
          ) : (
            <Input
              placeholder={searchPlaceholder}
              value={table.getState().globalFilter ?? ''}
              onChange={(event) => table.setGlobalFilter(event.target.value)}
              className='h-8 w-[150px] pr-8 lg:w-[250px]'
            />
          )}
          {isFiltered && (
            <Button
              type='button'
              variant='ghost'
              size='icon'
              onClick={() => {
                table.resetColumnFilters()
                table.setGlobalFilter('')
              }}
              className='absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2'
            >
              <Cross2Icon className='h-3.5 w-3.5' />
              <span className='sr-only'>Reset filters</span>
            </Button>
          )}
        </div>
        <div className='flex gap-x-2'>
          {filters.map((filter) => {
            const column = table.getColumn(filter.columnId)
            if (!column) return null
            return (
              <DataTableFacetedFilter
                key={filter.columnId}
                column={column}
                title={filter.title}
                options={filter.options}
              />
            )
          })}
        </div>
      </div>
      {createButton}
    </div>
  )
}
