import { useState, useEffect, useCallback } from 'react'
import type { NodeStatus, SystemStats } from '@/lib/api'
import { fetchNodes, fetchNodeStats, fetchNodeHistory } from '@/lib/api'

export function useNodes(interval = 5000) {
  const [nodes, setNodes] = useState<NodeStatus[]>([])
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const data = await fetchNodes()
      setNodes(data)
    } catch {
      // silent
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, interval)
    return () => clearInterval(id)
  }, [refresh, interval])

  return { nodes, loading, refresh }
}

export function useNodeStats(nodeId: string | null, interval = 5000) {
  const [stats, setStats] = useState<SystemStats | null>(null)
  const [history, setHistory] = useState<SystemStats[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!nodeId) {
      setStats(null)
      setHistory([])
      setLoading(false)
      return
    }

    let cancelled = false

    const refresh = async () => {
      try {
        const [s, h] = await Promise.all([
          fetchNodeStats(nodeId),
          fetchNodeHistory(nodeId, 30),
        ])
        if (!cancelled) {
          setStats(s)
          setHistory(h)
        }
      } catch {
        // silent
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    refresh()
    const id = setInterval(refresh, interval)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [nodeId, interval])

  return { stats, history, loading }
}
