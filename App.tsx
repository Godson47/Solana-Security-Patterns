import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import HomePage from './pages/HomePage';
import PatternPage from './pages/PatternPage';
import DeepDivePage from './pages/DeepDivePage';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/pattern/:id" element={<PatternPage />} />
        <Route path="/deep-dive" element={<DeepDivePage />} />
      </Routes>
    </Layout>
  );
}

export default App;
