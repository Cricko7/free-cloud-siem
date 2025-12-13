import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts'

const mockData = [
  { time: '14:00', cpu: 12, mem: 45 },
  { time: '14:02', cpu: 25, mem: 52 },
  { time: '14:04', cpu: 18, mem: 60 },
  { time: '14:06', cpu: 35, mem: 48 },
  { time: '14:08', cpu: 22, mem: 55 },
]

export default function MetricsChart() {
  return (
    <div className="bg-gray-800 rounded-xl p-6 shadow-2xl">
      <h2 className="text-2xl font-bold mb-6">📊 System Metrics</h2>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={mockData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis dataKey="time" stroke="#9CA3AF" />
          <YAxis stroke="#9CA3AF" />
          <Tooltip />
          <Line 
            type="monotone" 
            dataKey="cpu" 
            stroke="#3B82F6" 
            strokeWidth={3}
            name="CPU %"
          />
          <Line 
            type="monotone" 
            dataKey="mem" 
            stroke="#10B981" 
            strokeWidth={3}
            name="Memory %"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
