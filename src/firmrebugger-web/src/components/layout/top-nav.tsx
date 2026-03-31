import { useNavigate } from '@tanstack/react-router'
import { type LucideIcon, Menu } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

type TopNavProps = React.HTMLAttributes<HTMLElement> & {
  links: {
    title: string
    href: string
    isActive: boolean
    icon?: LucideIcon
    disabled?: boolean
  }[]
}

export function TopNav({ className, links, ...props }: TopNavProps) {
  const navigate = useNavigate()

  const handleNavigate = (to: string) => {
    void navigate({ to })
  }

  return (
    <>
      <div className='lg:hidden'>
        <DropdownMenu modal={false}>
          <DropdownMenuTrigger asChild>
            <Button
              size='icon'
              variant='outline'
              className='rounded-full border-primary/20 bg-background/80 shadow-sm md:size-7'
            >
              <Menu />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent side='bottom' align='end' className='w-52'>
            {links.map(({ title, href, isActive, icon: Icon, disabled }) => (
              <DropdownMenuItem
                key={`${title}-${href}`}
                className={cn(!isActive && 'text-muted-foreground')}
                disabled={disabled}
                onSelect={(event) => {
                  event.preventDefault()
                  if (!disabled) handleNavigate(href)
                }}
              >
                <span className='flex items-center gap-2'>
                  {Icon ? <Icon className='h-4 w-4' /> : null}
                  {title}
                </span>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <nav
        className={cn(
          'hidden rounded-full border border-border/60 bg-muted/40 p-1 shadow-sm backdrop-blur lg:flex',
          className
        )}
        {...props}
      >
        {links.map(({ title, href, isActive, icon: Icon, disabled }) => (
          <button
            type='button'
            key={`${title}-${href}`}
            disabled={disabled}
            onClick={() => handleNavigate(href)}
            className={cn(
              'inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium transition-all',
              'disabled:pointer-events-none disabled:opacity-50',
              'hover:bg-background/80 hover:text-foreground',
              isActive
                ? 'bg-background text-foreground shadow-xs ring-1 ring-border/80'
                : 'text-muted-foreground'
            )}
          >
            {Icon ? <Icon className='h-4 w-4' /> : null}
            {title}
          </button>
        ))}
      </nav>
    </>
  )
}
