import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Box, ArrowLeft, ArrowRight, Clock, Hash, Layers, FileText, ChevronRight } from 'lucide-react'
import { getBlock, formatHash, formatNumber, formatTime, BlockDetail } from '../api'

function InfoRow({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center py-3 border-b border-night-800/50 last:border-0">
      <span className="text-night-500 text-sm sm:w-40 shrink-0 mb-1 sm:mb-0">{label}</span>
      <span className={`${mono ? 'font-mono text-sm' : ''} text-night-100 break-all`}>{value}</span>
    </div>
  )
}

function BlockPage() {
  const { id } = useParams<{ id: string }>()
  
  const { data: block, isLoading, error } = useQuery({
    queryKey: ['block', id],
    queryFn: () => getBlock(id!),
    enabled: !!id,
  })

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-48 skeleton rounded" />
        <div className="card">
          <div className="space-y-4">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="h-6 skeleton rounded" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (error || !block) {
    return (
      <div className="card text-center py-12">
        <Box className="w-16 h-16 text-night-600 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-night-300 mb-2">Block Not Found</h2>
        <p className="text-night-500">The requested block could not be found.</p>
        <Link to="/" className="text-dsv-400 hover:text-dsv-300 mt-4 inline-block">
          ← Back to home
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-dsv-500 to-dsv-700 flex items-center justify-center glow">
            <Box className="w-7 h-7 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-night-100">
              Block #{formatNumber(block.height)}
            </h1>
            <p className="text-night-500 font-mono text-sm">{formatHash(block.hash, 12)}</p>
          </div>
        </div>
        
        {/* Navigation */}
        <div className="flex items-center gap-2">
          {block.height > 0 && (
            <Link 
              to={`/block/${block.height - 1}`}
              className="p-2 rounded-lg bg-night-800 hover:bg-night-700 transition-colors"
            >
              <ArrowLeft className="w-5 h-5 text-night-400" />
            </Link>
          )}
          <Link 
            to={`/block/${block.height + 1}`}
            className="p-2 rounded-lg bg-night-800 hover:bg-night-700 transition-colors"
          >
            <ArrowRight className="w-5 h-5 text-night-400" />
          </Link>
        </div>
      </div>

      {/* Block Info */}
      <div className="card">
        <h2 className="card-header flex items-center gap-2">
          <FileText className="w-5 h-5 text-dsv-400" />
          Block Details
        </h2>
        
        <div className="divide-y divide-night-800/50">
          <InfoRow label="Block Hash" value={block.hash} mono />
          <InfoRow label="Height" value={formatNumber(block.height)} />
          <InfoRow label="Timestamp" value={formatTime(block.time)} />
          <InfoRow label="Confirmations" value={
            <span className="badge badge-success">{formatNumber(block.confirmations)}</span>
          } />
          <InfoRow label="Transactions" value={formatNumber(block.tx_count)} />
          <InfoRow label="Size" value={`${formatNumber(block.size_bytes)} bytes`} />
          <InfoRow label="Difficulty" value={`0x${block.bits.toString(16)}`} mono />
          <InfoRow label="Nonce" value={formatNumber(block.nonce)} />
          <InfoRow label="Merkle Root" value={block.merkle} mono />
          <InfoRow label="Previous Block" value={
            block.prev_hash !== '0'.repeat(64) ? (
              <Link to={`/block/${block.prev_hash}`} className="hash-link">
                {block.prev_hash}
              </Link>
            ) : 'Genesis Block'
          } mono />
        </div>
      </div>

      {/* Transactions */}
      <div className="card">
        <h2 className="card-header flex items-center gap-2">
          <Layers className="w-5 h-5 text-dsv-400" />
          Transactions ({block.tx_count})
        </h2>
        
        <div className="space-y-2">
          {block.txids.map((txid, idx) => (
            <Link
              key={txid}
              to={`/tx/${txid}`}
              className="flex items-center justify-between p-3 rounded-lg bg-night-800/30 hover:bg-night-800/50 transition-colors group"
            >
              <div className="flex items-center gap-3">
                <span className="text-night-500 text-sm w-8">#{idx}</span>
                <span className="font-mono text-sm text-night-300 group-hover:text-dsv-400 transition-colors">
                  {formatHash(txid, 16)}
                </span>
                {idx === 0 && <span className="badge badge-info">Coinbase</span>}
              </div>
              <ChevronRight className="w-4 h-4 text-night-600 group-hover:text-dsv-400 transition-colors" />
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}

export default BlockPage

