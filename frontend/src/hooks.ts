import { useCallback, useEffect, useState } from 'react'

export interface Loaded<T> {
  data: T | null
  error: string | null
  reload: () => void
}

/** Fetches on mount and whenever `key` changes. A late reply for an old key is dropped. */
export function useData<T>(load: () => Promise<T>, key = ''): Loaded<T> {
  const [state, setState] = useState<{ data: T | null; error: string | null }>({
    data: null,
    error: null,
  })
  const [version, setVersion] = useState(0)

  useEffect(() => {
    let current = true
    load().then(
      (data) => current && setState({ data, error: null }),
      (error: Error) => current && setState({ data: null, error: error.message }),
    )
    return () => {
      current = false
    }
    // `load` is rebuilt on every render, and `key` says when it really changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, version])

  const reload = useCallback(() => setVersion((value) => value + 1), [])
  return { ...state, reload }
}

const ANALYST_KEY = 'threatpulse.analyst'

function readAnalyst(): string {
  try {
    return localStorage.getItem(ANALYST_KEY) ?? ''
  } catch {
    return ''
  }
}

/** A convenience only. The name is a typed claim, not a login (see backend/README.md). */
export function useAnalystName(): [string, (name: string) => void] {
  const [name, setName] = useState(readAnalyst)
  const update = useCallback((value: string) => {
    setName(value)
    try {
      localStorage.setItem(ANALYST_KEY, value)
    } catch {
      // Storage can be blocked. The name still works for this page.
    }
  }, [])
  return [name, update]
}
