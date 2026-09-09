import { BrowserRouter, Route, Routes, Navigate } from 'react-router-dom';
import { GlobalCursor } from './components/common/GlobalCursor';
import { LandingPage } from './pages/LandingPage';
import { PipelineLayout } from './components/layout/PipelineLayout';
import { NetworkStatePage } from './pages/NetworkStatePage';
import { TrajectoryForecastPage } from './pages/TrajectoryForecastPage';
import { InterventionMatrixPage } from './pages/InterventionMatrixPage';
import { HumanApprovalPage } from './pages/HumanApprovalPage';
import { VerificationPage } from './pages/VerificationPage';
import { AuditTracePage } from './pages/AuditTracePage';

export default function App() {
  return (
    <BrowserRouter>
      {/* Single Global Smooth Glowing Cursor Follower with Trailing Ring */}
      <GlobalCursor />

      <Routes>
        {/* Landing Page Route */}
        <Route path="/" element={<LandingPage />} />

        {/* Pipeline Defence Routes (Control Center) */}
        <Route path="/pipeline" element={<PipelineLayout />}>
          <Route index element={<Navigate to="/pipeline/observe" replace />} />
          <Route path="observe" element={<NetworkStatePage />} />
          <Route path="predict" element={<TrajectoryForecastPage />} />
          <Route path="trajectory" element={<TrajectoryForecastPage />} />
          <Route path="simulate" element={<InterventionMatrixPage />} />
          <Route path="intervention" element={<InterventionMatrixPage />} />
          <Route path="approve" element={<HumanApprovalPage />} />
          <Route path="verify" element={<VerificationPage />} />
          <Route path="trace" element={<AuditTracePage />} />
          <Route path="audit" element={<AuditTracePage />} />
          <Route path="*" element={<Navigate to="/pipeline/observe" replace />} />
        </Route>

        {/* Control center and legacy redirects */}
        <Route path="/control-center" element={<Navigate to="/pipeline/observe" replace />} />
        <Route path="/control-center/*" element={<Navigate to="/pipeline/observe" replace />} />
        <Route path="/command-center" element={<Navigate to="/pipeline/observe" replace />} />
        <Route path="/command-center/*" element={<Navigate to="/pipeline/observe" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
