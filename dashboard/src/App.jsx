import { useQuery } from '@tanstack/react-query'
import { useState, useEffect } from 'react'
import LogsTable from './components/LogsTable'
import AlertsBoard from './components/AlertsBoard'
import MetricsChart from './components/MetricsChart'

function App() {
  const { data: logsData, refetch: refetchLogs } = useQuery({
    queryKey: ['logs'],
    queryFn: () => fetch('http://localhost:8080/logs').then(res => res.json()) // ✅ Абсолютный URL
  })

  const { data: alertsData, refetch: refetchAlerts } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => fetch('http://localhost:8080/alerts').then(res => res.json()) // ✅ Абсолютный URL
  })

  useEffect(() => {
    const interval = setInterval(() => {
      refetchLogs()
      refetchAlerts()
    }, 2000)
    return () => clearInterval(interval)
  }, [refetchLogs, refetchAlerts])

  const logs = logsData?.logs || []
  const alerts = alertsData?.alerts || []

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        <header className="mb-12">
          <h1 className="text-5xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            🚨 SIEM Dashboard
          </h1>
          <p className="text-xl text-gray-400 mt-2">
            Hosts: {logs.length > 0 ? [...new Set(logs.map(l => l.host))].length : 0} | 
            Logs: {logs.length} | 
            Alerts: {alerts.length}
          </p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <AlertsBoard alerts={alerts} />
          <div className="lg:col-span-2">
            <LogsTable logs={logs} />
          </div>
        </div>
        <MetricsChart />
      </div>
    </div>
  )
}

export default App
