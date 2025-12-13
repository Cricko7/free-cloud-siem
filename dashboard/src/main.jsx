import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'  // ❌ Без этого пусто!
import App from './App.jsx'
import './index.css'

const queryClient = new QueryClient()

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>  {/* ❌ Без этого пусто! */}
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
