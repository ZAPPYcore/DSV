import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Box, ArrowRight, Clock, Hash, Layers } from 'lucide-react'
import { getChainInfo, getBlocks, formatHash, formatNumber, timeAgo, ChainInfo, BlockSummary } from '../api'

function StatCard({ title, value, icon: Icon, color }: { 
  title: string
  value: string | number
  icon: any
  color: string 
}) {
  return (
    <div className="card group hover:border-night-700 transition-all">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-night-400 text-sm mb-1">{title}</p>
          <p className="text-2xl font-bold text-night-100">{value}</p>
        </div>
        <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center opacity-80 group-hover:opacity-100 transition-opacity`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  )
}

function BlockCard({ block }: { block: BlockSummary }) {
  return (
    <Link 
      to={`/block/${block.height}`}
      className="card group hover:border-dsv-500/50 hover:glow transition-all animate-fade-in"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-dsv-500/10 flex items-center justify-center">
            <Box className="w-6 h-6 text-dsv-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-night-100">Block {formatNumber(block.height)}</span>
              <span className="badge badge-info">{block.tx_count} txs</span>
            </div>
            <p className="text-night-500 text-sm font-mono mt-1">
              {formatHash(block.hash)}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-night-500 text-sm">{timeAgo(block.time)}</span>
          <ArrowRight className="w-5 h-5 text-night-600 group-hover:text-dsv-400 group-hover:translate-x-1 transition-all" />
        </div>
      </div>
    </Link>
  )
}

function HomePage() {
  const { data: chainInfo, isLoading: chainLoading } = useQuery({
    queryKey: ['chainInfo'],
    queryFn: getChainInfo,
  })

  const { data: blocks, isLoading: blocksLoading } = useQuery({
    queryKey: ['latestBlocks'],
    queryFn: () => getBlocks(10),
    refetchInterval: 15000,
  })

  return (
    <div className="space-y-8">
      {/* Hero */}
      <div className="text-center py-8">
        <h1 className="text-4xl font-bold mb-4">
          <span className="bg-gradient-to-r from-dsv-400 via-dsv-300 to-dsv-500 bg-clip-text text-transparent">
            DSV Block Explorer
          </span>
        </h1>
        <p className="text-night-400 text-lg">
          Explore the Dynamic Storage of Value blockchain
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatCard
          title="Block Height"
          value={chainInfo ? formatNumber(chainInfo.best_height) : '...'}
          icon={Layers}
          color="from-dsv-500 to-dsv-700"
        />
        <StatCard
          title="Latest Block"
          value={chainInfo ? formatHash(chainInfo.best_tip_hash, 6) : '...'}
          icon={Hash}
          color="from-violet-500 to-violet-700"
        />
        <StatCard
          title="Last Updated"
          value={chainInfo ? timeAgo(chainInfo.updated_at) : '...'}
          icon={Clock}
          color="from-emerald-500 to-emerald-700"
        />
      </div>

      {/* Latest Blocks */}
      <div>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-night-100">Latest Blocks</h2>
          <Link 
            to="/blocks" 
            className="text-dsv-400 hover:text-dsv-300 text-sm flex items-center gap-1 transition-colors"
          >
            View all <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
        
        {blocksLoading ? (
          <div className="space-y-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="card">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-xl skeleton" />
                  <div className="flex-1 space-y-2">
                    <div className="h-5 w-32 skeleton rounded" />
                    <div className="h-4 w-48 skeleton rounded" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="space-y-4">
            {blocks?.map((block) => (
              <BlockCard key={block.hash} block={block} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default HomePage

