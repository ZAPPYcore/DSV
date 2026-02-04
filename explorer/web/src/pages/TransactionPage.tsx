import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { FileText, ArrowRight, ArrowDownRight, ArrowUpRight, Box, Check, X } from 'lucide-react'
import { getTransaction, formatHash, formatNumber, formatAmount, TransactionDetail } from '../api'

function TransactionPage() {
  const { txid } = useParams<{ txid: string }>()
  
  const { data: tx, isLoading, error } = useQuery({
    queryKey: ['transaction', txid],
    queryFn: () => getTransaction(txid!),
    enabled: !!txid,
  })

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-64 skeleton rounded" />
        <div className="card">
          <div className="space-y-4">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-6 skeleton rounded" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (error || !tx) {
    return (
      <div className="card text-center py-12">
        <FileText className="w-16 h-16 text-night-600 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-night-300 mb-2">Transaction Not Found</h2>
        <p className="text-night-500">The requested transaction could not be found.</p>
        <Link to="/" className="text-dsv-400 hover:text-dsv-300 mt-4 inline-block">
          ← Back to home
        </Link>
      </div>
    )
  }

  const isCoinbase = tx.inputs.length === 1 && tx.inputs[0].is_coinbase

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-violet-500 to-violet-700 flex items-center justify-center glow">
          <FileText className="w-7 h-7 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-night-100">Transaction</h1>
          <p className="text-night-500 font-mono text-sm">{formatHash(tx.txid, 16)}</p>
        </div>
      </div>

      {/* Summary Card */}
      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div>
            <p className="text-night-500 text-sm mb-1">Block</p>
            <Link to={`/block/${tx.block_height}`} className="text-dsv-400 hover:text-dsv-300 font-semibold">
              #{formatNumber(tx.block_height)}
            </Link>
          </div>
          <div>
            <p className="text-night-500 text-sm mb-1">Confirmations</p>
            <span className="badge badge-success">{formatNumber(tx.confirmations)}</span>
          </div>
          <div>
            <p className="text-night-500 text-sm mb-1">Fee</p>
            <p className="text-night-100">{formatAmount(tx.fee)}</p>
          </div>
          <div>
            <p className="text-night-500 text-sm mb-1">Size</p>
            <p className="text-night-100">{formatNumber(tx.size_bytes)} bytes</p>
          </div>
        </div>
      </div>

      {/* Full TXID */}
      <div className="card">
        <h2 className="text-sm text-night-500 mb-2">Transaction ID</h2>
        <p className="font-mono text-sm text-night-200 break-all">{tx.txid}</p>
      </div>

      {/* Inputs and Outputs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Inputs */}
        <div className="card">
          <h2 className="card-header flex items-center gap-2">
            <ArrowDownRight className="w-5 h-5 text-rose-400" />
            Inputs ({tx.inputs.length})
          </h2>
          
          <div className="space-y-3">
            {tx.inputs.map((input, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-night-800/30">
                {input.is_coinbase ? (
                  <div className="flex items-center gap-2">
                    <span className="badge badge-info">Coinbase</span>
                    <span className="text-night-500 text-sm">Block Reward</span>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between mb-2">
                      {input.address ? (
                        <Link to={`/address/${input.address}`} className="hash-link text-sm font-mono">
                          {formatHash(input.address, 12)}
                        </Link>
                      ) : (
                        <span className="text-night-500 text-sm">Unknown</span>
                      )}
                      {input.amount && (
                        <span className="text-night-200 text-sm">{formatAmount(input.amount)}</span>
                      )}
                    </div>
                    <div className="text-night-500 text-xs font-mono">
                      From: {formatHash(input.prev_txid, 8)}:{input.prev_vout}
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Outputs */}
        <div className="card">
          <h2 className="card-header flex items-center gap-2">
            <ArrowUpRight className="w-5 h-5 text-emerald-400" />
            Outputs ({tx.outputs.length})
          </h2>
          
          <div className="space-y-3">
            {tx.outputs.map((output, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-night-800/30">
                <div className="flex items-center justify-between mb-2">
                  <Link to={`/address/${output.address}`} className="hash-link text-sm font-mono">
                    {formatHash(output.address, 12)}
                  </Link>
                  <span className="text-night-200 text-sm">{formatAmount(output.amount)}</span>
                </div>
                <div className="flex items-center gap-2">
                  {output.spent_by ? (
                    <>
                      <X className="w-3 h-3 text-rose-400" />
                      <Link to={`/tx/${output.spent_by}`} className="text-night-500 text-xs font-mono hover:text-dsv-400">
                        Spent in {formatHash(output.spent_by, 8)}
                      </Link>
                    </>
                  ) : (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400 text-xs">Unspent</span>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default TransactionPage

