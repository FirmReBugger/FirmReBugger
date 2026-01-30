import {
  LayoutDashboard,
  ListTodo,
  Command,
} from 'lucide-react'
import { type SidebarData } from '../types'

export const sidebarData: SidebarData = {
  teams: [
    {
      name: 'FirmReBugger',
      logo: Command,
      plan: 'Benchmark',
    },
  ],
  navGroups: [
    {
      title: 'General',
      items: [
        {
          title: 'Report',
          url: '/',
          icon: LayoutDashboard,
        },
        {
          title: 'Job manager',
          url: '/manager',
          icon: ListTodo,
        },
      ],
    },
  ],
}
