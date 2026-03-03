import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Toaster } from '@/components/ui/sonner';
import LandingPage from '@/pages/LandingPage';
import UploadPage from '@/pages/UploadPage';
import AnalysisPage from '@/pages/AnalysisPage';
import DashboardPage from '@/pages/DashboardPage';
import ReportPage from '@/pages/ReportPage';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-cyber-darker">
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/upload" element={<UploadPage />} />
          <Route path="/analysis/:id" element={<AnalysisPage />} />
          <Route path="/dashboard/:id" element={<DashboardPage />} />
          <Route path="/report/:id" element={<ReportPage />} />
        </Routes>
        <Toaster />
      </div>
    </Router>
  );
}

export default App;
