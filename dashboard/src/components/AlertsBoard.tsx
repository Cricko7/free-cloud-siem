export default function AlertsBoard({ alerts }) {
  const highAlerts = alerts.filter(a => a.severity === 'HIGH')
  const mediumAlerts = alerts.filter(a => a.severity === 'MEDIUM')

  return (
    <div className="bg-gray-800 rounded-xl p-6 shadow-2xl h-full">
      <h2 className="text-2xl font-bold mb-6 flex items-center">
        🚨 Active Alerts
        <span className="ml-4 px-3 py-1 bg-red-600 text-white rounded-full text-sm font-bold">
          {alerts.length}
        </span>
      </h2>
      
      <div className="space-y-4">
        {highAlerts.slice(0, 5).map((alert, i) => (
          <div key={i} className="bg-red-900/50 border border-red-500 p-4 rounded-lg">
            <div className="flex justify-between items-start mb-2">
              <span className="font-bold text-red-300">{alert.type}</span>
              <span className="text-xs opacity-75">{new Date(alert.ts).toLocaleTimeString()}</span>
            </div>
            <p className="text-sm">{alert.message}</p>
            <span className="text-xs bg-red-500/20 px-2 py-1 rounded mt-2 inline-block">
              {alert.host}
            </span>
          </div>
        ))}
        
        {mediumAlerts.slice(0, 3).map((alert, i) => (
          <div key={i} className="bg-yellow-900/30 border border-yellow-500 p-4 rounded-lg">
            <div className="flex justify-between items-start mb-2">
              <span className="font-bold text-yellow-300">{alert.type}</span>
              <span className="text-xs opacity-75">{new Date(alert.ts).toLocaleTimeString()}</span>
            </div>
            <p className="text-sm">{alert.message}</p>
          </div>
        ))}
      </div>
      
      {alerts.length === 0 && (
        <div className="text-center py-12 text-gray-500">
          ✅ No active alerts
        </div>
      )}
    </div>
  )
}
