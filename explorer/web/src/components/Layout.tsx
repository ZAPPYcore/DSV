import { ReactNode, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search, Box, Activity, ChevronRight } from 'lucide-react'
import { getChainInfo, search, formatNumber } from '../api'

interface LayoutProps {
  children: ReactNode
}

function Layout({ children }: LayoutProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const navigate = useNavigate()
  
  const { data: chainInfo } = useQuery({
    queryKey: ['chainInfo'],
    queryFn: getChainInfo,
    refetchInterval: 10000,
  })

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!searchQuery.trim()) return
    
    setIsSearching(true)
    try {
      const result = await search(searchQuery.trim())
      if (result.type === 'block') {
        navigate(`/block/${result.value}`)
      } else if (result.type === 'transaction') {
        navigate(`/tx/${result.value}`)
      } else if (result.type === 'address') {
        navigate(`/address/${result.value}`)
      }
      setSearchQuery('')
    } catch (error) {
      alert('Not found')
    } finally {
      setIsSearching(false)
    }
  }

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="border-b border-night-800 bg-night-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-3 group">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-dsv-500 to-dsv-700 flex items-center justify-center glow-hover transition-all">
                <Box className="w-5 h-5 text-white" />
              </div>
              <div>
                <span className="text-xl font-bold bg-gradient-to-r from-dsv-400 to-dsv-200 bg-clip-text text-transparent">
                  DSV
                </span>
                <span className="text-night-400 text-sm block -mt-1">Explorer</span>
              </div>
            </Link>

            {/* Search */}
            <form onSubmit={handleSearch} className="flex-1 max-w-xl mx-8">
              <div className="relative">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-night-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search by block, transaction, or address..."
                  className="w-full bg-night-900 border border-night-700 rounded-xl pl-12 pr-4 py-3 text-sm placeholder-night-500 focus:outline-none focus:border-dsv-500 focus:ring-1 focus:ring-dsv-500 transition-all"
                  disabled={isSearching}
                />
              </div>
            </form>

            {/* Chain Stats */}
            <div className="flex items-center gap-6 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse-slow"></div>
                <span className="text-night-400">Block</span>
                <span className="font-mono font-semibold text-night-100">
                  {chainInfo ? formatNumber(chainInfo.best_height) : '...'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-night-800 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-night-500 text-sm">
              <Activity className="w-4 h-4" />
              <span>Dynamic Storage of Value</span>
            </div>
            <div className="flex items-center gap-6 text-sm text-night-500">
              <a href="https://github.com/dsv" className="hover:text-night-300 transition-colors">
                GitHub
              </a>
              <a href="/api/health" className="hover:text-night-300 transition-colors">
                API Status
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default Layout

