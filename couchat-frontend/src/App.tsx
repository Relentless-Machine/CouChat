import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import LoginPage from './pages/LoginPage';
import ChatPage from './pages/ChatPage';
import ProtectedRoute from './components/ProtectedRoute';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <HashRouter> { /* Changed from BrowserRouter to HashRouter */ }
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/chat" element={<ProtectedRoute />}>
            <Route index element={<ChatPage />} />
          </Route>
          <Route path="/" element={<Navigate replace to="/login" />} />
        </Routes>
      </HashRouter>
    </AuthProvider>
  );
}

export default App;
