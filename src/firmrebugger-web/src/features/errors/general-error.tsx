export function GeneralError() {
  return (
    <div className='flex h-screen w-full flex-col items-center justify-center'>
      <h1 className='text-4xl font-bold'>Oops!</h1>
      <p className='text-muted-foreground mt-2'>Something went wrong.</p>
    </div>
  )
}
