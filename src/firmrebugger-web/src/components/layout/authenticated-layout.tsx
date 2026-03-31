import { useEffect, useState } from 'react'
import { Link, Outlet, useLocation } from '@tanstack/react-router'
import { BarChart3, ClipboardList } from 'lucide-react'
import { cn } from '@/lib/utils'
import { TopNav } from '@/components/layout/top-nav'

type AuthenticatedLayoutProps = {
  children?: React.ReactNode
}

export function AuthenticatedLayout({ children }: AuthenticatedLayoutProps) {
  const { pathname } = useLocation()
  const [hasOverlayOpen, setHasOverlayOpen] = useState(false)

  useEffect(() => {
    const checkOverlay = () => {
      const openOverlay = Boolean(
        document.querySelector('[data-slot="dialog-content"]') ||
          document.querySelector('[data-slot="sheet-content"]') ||
          document.querySelector('[data-slot="alert-dialog-content"]') ||
          document.querySelector('[data-slot="dialog-overlay"]') ||
          document.querySelector('[data-slot="sheet-overlay"]') ||
          document.querySelector('[data-slot="alert-dialog-overlay"]')
      )
      setHasOverlayOpen(openOverlay)
    }

    checkOverlay()

    const observer = new MutationObserver(checkOverlay)
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['data-state'],
    })

    return () => {
      observer.disconnect()
    }
  }, [])

  const isStickyPage =
    pathname === '/' || pathname.startsWith('/report') || pathname.startsWith('/manager')
  const stickyEnabled = isStickyPage && !hasOverlayOpen

  const links = [
    {
      title: 'Report',
      href: '/',
      isActive: pathname === '/' || pathname.startsWith('/report'),
      icon: BarChart3,
    },
    {
      title: 'Job manager',
      href: '/manager',
      isActive: pathname.startsWith('/manager'),
      icon: ClipboardList,
    },
  ]

  return (
    <div className='min-h-svh bg-gradient-to-b from-muted/30 via-background to-background px-3 py-3 sm:px-4 sm:py-4'>
      <div className='mx-auto w-full max-w-7xl overflow-visible rounded-3xl border border-border/70 bg-card shadow-xl'>
        <header
          className={cn(
            'border-b border-border/60 bg-background/90 backdrop-blur supports-backdrop-filter:bg-background/75',
            stickyEnabled ? 'sticky top-0 z-[60]' : 'relative z-10'
          )}
        >
          <div className='flex h-20 items-center justify-between px-4 sm:px-6'>
            <Link to='/' className='group inline-flex items-center gap-2'>
              <span className='rounded-full bg-primary/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-widest text-primary'>
                FRB
              </span>
              <span className='flex flex-col leading-tight'>
                <span className='text-sm font-bold tracking-wide transition-colors group-hover:text-primary'>
                  FirmReBugger
                </span>
                <span className='text-[11px] text-muted-foreground/70'>
                  A benchmark framework for monolithic firmware fuzzers.
                </span>
              </span>
            </Link>
            <TopNav links={links} />
          </div>
        </header>
        <main
          className={cn(
            '@container/content',
            'has-data-[layout=fixed]:h-svh',
            'bg-gradient-to-b from-background to-muted/10 px-4 py-5 sm:px-6 sm:py-6'
          )}
        >
          {children ?? <Outlet />}
        </main>
      </div>
    </div>
  )
}
