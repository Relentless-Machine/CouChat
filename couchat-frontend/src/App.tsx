import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import ChatPage from './pages/ChatPage'; // Import ChatPage
import './App.css';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/chat" element={<ChatPage />} />
        <Route path="/" element={<Navigate replace to="/login" />} /> {/* Default redirect to login */}
      </Routes>
    </BrowserRouter>
  );
}

export default App;
