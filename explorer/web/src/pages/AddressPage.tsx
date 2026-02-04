import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Wallet, ArrowDownRight, ArrowUpRight, Coins, Activity, ChevronRight } from 'lucide-react'
import { getAddress, getAddressUtxos, formatHash, formatNumber, formatAmount, AddressInfo, UTXO } from '../api'

function StatBox({ label, value, icon: Icon, color }: {
  label: string
  value: string
  icon: any
  color: string
}) {
  return (
    <div className="flex items-center gap-4 p-4 rounded-xl bg-night-800/30">
      <div className={`w-10 h-10 rounded-lg ${color} flex items-center justify-center`}>
        <Icon className="w-5 h-5 text-white" />
      </div>
      <div>
        <p className="text-night-500 text-sm">{label}</p>
        <p className="text-night-100 font-semibold">{value}</p>
      </div>
    </div>
  )
}

function AddressPage() {
  const { address } = useParams<{ address: string }>()
  
  const { data: info, isLoading: infoLoading, error } = useQuery({
    queryKey: ['address', address],
    queryFn: () => getAddress(address!),
    enabled: !!address,
  })

  const { data: utxos, isLoading: utxosLoading } = useQuery({
    queryKey: ['addressUtxos', address],
    queryFn: () => getAddressUtxos(address!),
    enabled: !!address,
  })

  if (infoLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-64 skeleton rounded" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 skeleton rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card text-center py-12">
        <Wallet className="w-16 h-16 text-night-600 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-night-300 mb-2">Address Not Found</h2>
        <p className="text-night-500">The requested address could not be found.</p>
        <Link to="/" className="text-dsv-400 hover:text-dsv-300 mt-4 inline-block">
          ← Back to home
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-emerald-500 to-emerald-700 flex items-center justify-center glow">
          <Wallet className="w-7 h-7 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-night-100">Address</h1>
          <p className="text-night-500 font-mono text-sm">{address}</p>
        </div>
      </div>

      {/* Stats */}
      {info && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatBox
            label="Balance"
            value={formatAmount(info.balance)}
            icon={Coins}
            color="bg-emerald-500/20"
          />
          <StatBox
            label="Total Received"
            value={formatAmount(info.total_received)}
            icon={ArrowDownRight}
            color="bg-dsv-500/20"
          />
          <StatBox
            label="Total Sent"
            value={formatAmount(info.total_sent)}
            icon={ArrowUpRight}
            color="bg-rose-500/20"
          />
          <StatBox
            label="Transactions"
            value={formatNumber(info.tx_count)}
            icon={Activity}
            color="bg-violet-500/20"
          />
        </div>
      )}

      {/* Address Details */}
      <div className="card">
        <h2 className="card-header">Address Details</h2>
        <div className="space-y-3">
          <div className="flex justify-between py-2 border-b border-night-800/50">
            <span className="text-night-500">Full Address</span>
            <span className="font-mono text-sm text-night-200 break-all">{address}</span>
          </div>
          {info && (
            <>
              <div className="flex justify-between py-2 border-b border-night-800/50">
                <span className="text-night-500">UTXO Count</span>
                <span className="text-night-200">{formatNumber(info.utxo_count)}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-night-800/50">
                <span className="text-night-500">First Seen</span>
                <span className="text-night-200">
                  {info.first_seen_height !== null ? (
                    <Link to={`/block/${info.first_seen_height}`} className="text-dsv-400 hover:text-dsv-300">
                      Block #{formatNumber(info.first_seen_height)}
                    </Link>
                  ) : 'Never'}
                </span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-night-500">Last Seen</span>
                <span className="text-night-200">
                  {info.last_seen_height !== null ? (
                    <Link to={`/block/${info.last_seen_height}`} className="text-dsv-400 hover:text-dsv-300">
                      Block #{formatNumber(info.last_seen_height)}
                    </Link>
                  ) : 'Never'}
                </span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* UTXOs */}
      <div className="card">
        <h2 className="card-header flex items-center gap-2">
          <Coins className="w-5 h-5 text-emerald-400" />
          Unspent Outputs ({utxos?.length || 0})
        </h2>
        
        {utxosLoading ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-16 skeleton rounded-lg" />
            ))}
          </div>
        ) : utxos && utxos.length > 0 ? (
          <div className="space-y-2">
            {utxos.map((utxo, idx) => (
              <Link
                key={`${utxo.txid}:${utxo.vout}`}
                to={`/tx/${utxo.txid}`}
                className="flex items-center justify-between p-3 rounded-lg bg-night-800/30 hover:bg-night-800/50 transition-colors group"
              >
                <div>
                  <p className="font-mono text-sm text-night-300 group-hover:text-dsv-400 transition-colors">
                    {formatHash(utxo.txid, 12)}:{utxo.vout}
                  </p>
                  <p className="text-night-500 text-xs mt-1">
                    Block #{formatNumber(utxo.height)}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-emerald-400 font-medium">{formatAmount(utxo.amount)}</span>
                  <ChevronRight className="w-4 h-4 text-night-600 group-hover:text-dsv-400 transition-colors" />
                </div>
              </Link>
            ))}
          </div>
        ) : (
          <p className="text-night-500 text-center py-8">No unspent outputs</p>
        )}
      </div>
    </div>
  )
}

export default AddressPage

