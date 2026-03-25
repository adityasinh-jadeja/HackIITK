import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import BrowserUI from './components/BrowserUI';
import Dashboard from './components/Dashboard';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<BrowserUI />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
