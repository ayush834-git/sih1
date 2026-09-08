import { BrowserRouter, Route, Routes, Navigate } from 'react-router-dom';
import { LandingPage } from './pages/LandingPage';
import { ControlCenterLayout } from './components/layout/ControlCenterLayout';
import { OverviewPage } from './pages/OverviewPage';
import { InvestigationWorkspacePage } from './pages/InvestigationWorkspacePage';
import { EntityExplorerPage } from './pages/EntityExplorerPage';
import { EvidenceIntelligencePage } from './pages/EvidenceIntelligencePage';
import { AlertsQueuePage } from './pages/AlertsQueuePage';
import { SystemHealthAuditPage } from './pages/SystemHealthAuditPage';
import { SettingsWorkspacePage } from './pages/SettingsWorkspacePage';
import { OperationalSimulationPage } from './pages/OperationalSimulationPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />

        {/* Unified Control Centre Routes */}
        <Route path="/command-center" element={<ControlCenterLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="investigations" element={<InvestigationWorkspacePage />} />
          <Route path="intelligence" element={<EntityExplorerPage />} />
          <Route path="evidence" element={<EvidenceIntelligencePage />} />
          <Route path="alerts" element={<AlertsQueuePage />} />
          <Route path="review_queue" element={<AlertsQueuePage />} />
          <Route path="system" element={<SystemHealthAuditPage />} />
          <Route path="settings" element={<SettingsWorkspacePage />} />
          <Route path="simulation" element={<OperationalSimulationPage />} />
          <Route path="*" element={<Navigate to="/command-center" replace />} />
        </Route>

        <Route path="*" element={<Navigate to="/command-center" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
