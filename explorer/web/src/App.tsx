import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import BlockPage from './pages/BlockPage'
import TransactionPage from './pages/TransactionPage'
import AddressPage from './pages/AddressPage'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/block/:id" element={<BlockPage />} />
        <Route path="/tx/:txid" element={<TransactionPage />} />
        <Route path="/address/:address" element={<AddressPage />} />
      </Routes>
    </Layout>
  )
}

export default App

