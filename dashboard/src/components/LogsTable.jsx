export default function LogsTable({ logs }) {
  const [filter, setFilter] = useState('all')

  const filteredLogs = logs.filter(log => 
    filter === 'all' || log.level === filter
  )

  return (
    <div className="bg-gray-800 rounded-xl p-6 shadow-2xl">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold">📋 Recent Logs</h2>
        <select 
          className="bg-gray-700 px-4 py-2 rounded-lg"
          value={filter} 
          onChange={(e) => setFilter(e.target.value)}
        >
          <option value="all">All</option>
          <option value="security">Security</option>
          <option value="error">Error</option>
          <option value="info">Info</option>
        </select>
      </div>
      
      <div className="overflow-x-auto max-h-96 overflow-y-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="py-3 text-left w-32">Time</th>
              <th className="py-3 text-left w-24">Host</th>
              <th className="py-3 text-left w-24">Level</th>
              <th className="py-3 text-left">Message</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.slice(0, 50).map((log, i) => (
              <tr key={i} className="border-b border-gray-700 hover:bg-gray-700/50">
                <td className="py-3 font-mono text-xs opacity-75">
                  {log.ts ? new Date(log.ts).toLocaleTimeString() : 'N/A'}
                </td>
                <td className="py-3 font-mono text-sm">{log.host}</td>
                <td>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                    log.level === 'security' ? 'bg-red-500/20 text-red-300' :
                    log.level === 'error' ? 'bg-yellow-500/20 text-yellow-300' :
                    'bg-green-500/20 text-green-300'
                  }`}>
                    {log.level?.toUpperCase() || 'INFO'}
                  </span>
                </td>
                <td className="py-3 max-w-md truncate">{log.msg}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
