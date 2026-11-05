import { NavLink, Route, Routes } from 'react-router-dom'
import { AlertDetail } from './pages/AlertDetail'
import { AlertList } from './pages/AlertList'
import { Approvals } from './pages/Approvals'
import { FimChanges } from './pages/FimChanges'
import { Stats } from './pages/Stats'

export function App() {
  return (
    <>
      <header className="topbar">
        <span className="brand">ThreatPulse</span>
        <nav>
          <NavLink to="/" end>Alerts</NavLink>
          <NavLink to="/approvals">Approvals</NavLink>
          <NavLink to="/fim">FIM changes</NavLink>
          <NavLink to="/stats">Stats</NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<AlertList />} />
          <Route path="/alerts/:alertId" element={<AlertDetail />} />
          <Route path="/approvals" element={<Approvals />} />
          <Route path="/fim" element={<FimChanges />} />
          <Route path="/stats" element={<Stats />} />
          <Route path="*" element={<p>Page not found.</p>} />
        </Routes>
      </main>
    </>
  )
}
