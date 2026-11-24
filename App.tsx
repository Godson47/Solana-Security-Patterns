import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './Layout';
import HomePage from './HomePage';
import PatternPage from './PatternPage';
import DeepDivePage from './DeepDivePage';

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
