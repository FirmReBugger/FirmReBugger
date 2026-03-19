import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'

interface ApiUrlContextValue {
  apiUrl: string
  loading: boolean
}

const ApiUrlContext = createContext<ApiUrlContextValue>({
  apiUrl: '',
  loading: true,
})

export function ApiUrlProvider({ children }: { children: ReactNode }) {
  const [apiUrl, setApiUrl] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/config')
      .then((res) => res.json())
      .then((data) => {
        setApiUrl(data.apiUrl ?? '')
      })
      .catch(() => {
        // Fall back to same origin if the endpoint is unreachable
        setApiUrl('')
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  return (
    <ApiUrlContext.Provider value={{ apiUrl, loading }}>
      {children}
    </ApiUrlContext.Provider>
  )
}

export function useApiUrl(): string {
  return useContext(ApiUrlContext).apiUrl
}

export function useApiUrlLoading(): boolean {
  return useContext(ApiUrlContext).loading
}
