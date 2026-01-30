import { createFileRoute } from '@tanstack/react-router'
import { Manager } from '@/features/manager'

export const Route = createFileRoute('/_authenticated/manager/')({
  component: Manager,
})
