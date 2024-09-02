import type { NextPage } from 'next'
import NpmAuditDashboard from '../components/NpmAuditDashboard'

const Home: NextPage = () => {
  return (
    <div className="min-h-screen bg-gray-100">
      <NpmAuditDashboard />
    </div>
  )
}

export default Home