import { Routes, Route, Navigate } from "react-router-dom";
import { ToastProvider } from "@/components/shared";
import { AppLayout } from "@/components/layout/AppLayout";
import { Overview } from "@/pages/Overview";
import { M1 } from "@/pages/M1";
import { M2 } from "@/pages/M2";
import { M3 } from "@/pages/M3";
import { M4 } from "@/pages/M4";
import { M5 } from "@/pages/M5";
import { Pipeline } from "@/pages/Pipeline";
import { AI } from "@/pages/AI";
import { Jobs } from "@/pages/Jobs";
import { Settings } from "@/pages/Settings";

function App() {
  return (
    <ToastProvider>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Overview />} />
          <Route path="m1" element={<M1 />} />
          <Route path="m2" element={<M2 />} />
          <Route path="m3" element={<M3 />} />
          <Route path="m4" element={<M4 />} />
          <Route path="m5" element={<M5 />} />
          <Route path="pipeline" element={<Pipeline />} />
          <Route path="ai" element={<AI />} />
          <Route path="jobs" element={<Jobs />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </ToastProvider>
  );
}

export default App;
