import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api'

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
})

export interface ChainInfo {
  best_tip_hash: string
  best_height: number
  best_chainwork: string
  updated_at: string
}

export interface BlockSummary {
  hash: string
  height: number
  time: string
  tx_count: number
}

export interface BlockDetail {
  hash: string
  height: number
  prev_hash: string
  time: string
  bits: number
  nonce: number
  merkle: string
  chainwork: string
  tx_count: number
  size_bytes: number
  confirmations: number
  txids: string[]
}

export interface TransactionInput {
  n: number
  prev_txid: string
  prev_vout: number
  address: string | null
  amount: string | null
  is_coinbase: boolean
}

export interface TransactionOutput {
  n: number
  address: string
  amount: string
  spent_by: string | null
  spent_at_height: number | null
}

export interface TransactionDetail {
  txid: string
  block_hash: string
  block_height: number
  idx_in_block: number
  fee: string
  size_bytes: number
  confirmations: number
  inputs: TransactionInput[]
  outputs: TransactionOutput[]
}

export interface AddressInfo {
  address: string
  balance: string
  total_received: string
  total_sent: string
  utxo_count: number
  tx_count: number
  first_seen_height: number | null
  last_seen_height: number | null
}

export interface UTXO {
  txid: string
  vout: number
  amount: string
  height: number
}

export interface SearchResult {
  type: 'block' | 'transaction' | 'address'
  value: string
}

export const getChainInfo = async (): Promise<ChainInfo> => {
  const { data } = await api.get<ChainInfo>('/chain')
  return data
}

export const getBlocks = async (limit = 10, cursor?: number): Promise<BlockSummary[]> => {
  const params = new URLSearchParams({ limit: String(limit) })
  if (cursor !== undefined) params.append('cursor', String(cursor))
  const { data } = await api.get<BlockSummary[]>(`/blocks?${params}`)
  return data
}

export const getBlock = async (id: string): Promise<BlockDetail> => {
  const { data } = await api.get<BlockDetail>(`/block/${id}`)
  return data
}

export const getTransaction = async (txid: string): Promise<TransactionDetail> => {
  const { data } = await api.get<TransactionDetail>(`/tx/${txid}`)
  return data
}

export const getAddress = async (address: string): Promise<AddressInfo> => {
  const { data } = await api.get<AddressInfo>(`/address/${address}`)
  return data
}

export const getAddressUtxos = async (address: string): Promise<UTXO[]> => {
  const { data } = await api.get<UTXO[]>(`/address/${address}/utxos`)
  return data
}

export const search = async (query: string): Promise<SearchResult> => {
  const { data } = await api.get<SearchResult>(`/search?q=${encodeURIComponent(query)}`)
  return data
}

// Format helpers
export function formatHash(hash: string, length = 8): string {
  if (hash.length <= length * 2) return hash
  return `${hash.slice(0, length)}...${hash.slice(-length)}`
}

export function formatAmount(lgb: string): string {
  // For display, we'd convert from LGB to DSV
  // 1 DSV = 10^72 LGB
  try {
    const value = BigInt(lgb)
    if (value === 0n) return '0 DSV'
    
    // Simplified display
    const dsv = value.toString()
    if (dsv.length > 72) {
      const intPart = dsv.slice(0, dsv.length - 72)
      return `${intPart} DSV`
    }
    return `0.${dsv.padStart(72, '0').replace(/0+$/, '') || '0'} DSV`
  } catch {
    return lgb + ' LGB'
  }
}

export function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num)
}

export function formatTime(isoString: string): string {
  return new Date(isoString).toLocaleString()
}

export function timeAgo(isoString: string): string {
  const date = new Date(isoString)
  const now = new Date()
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000)
  
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

