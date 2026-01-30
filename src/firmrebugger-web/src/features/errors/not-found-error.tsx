export function NotFoundError() {
  return (
    <div className='flex h-screen w-full flex-col items-center justify-center'>
      <h1 className='text-4xl font-bold'>404</h1>
      <p className='text-muted-foreground mt-2'>Page not found.</p>
    </div>
  )
}
