import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Mfa from './components/Mfa';
import Reset from './components/Reset';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/login" />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/mfa" element={<Mfa />} />
        <Route path="/reset" element={<Reset />} />
      </Routes>
    </Router>
  );
}

export default App;
