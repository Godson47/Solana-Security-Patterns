import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, BookOpen, Home, Github, ExternalLink } from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation();

  const navItems = [
    { path: '/', label: 'Patterns', icon: Home },
    { path: '/deep-dive', label: 'Deep Dive', icon: BookOpen },
  ];

  return (
    <div className="min-h-screen bg-background relative">
      {/* Animated background */}
      <div className="fixed inset-0 bg-grid opacity-50 pointer-events-none" />
      <div className="fixed inset-0 noise-overlay pointer-events-none" />
      
      {/* Floating orbs */}
      <div className="fixed top-20 left-10 w-72 h-72 bg-primary/10 rounded-full blur-3xl animate-pulse-slow pointer-events-none" />
      <div className="fixed bottom-20 right-10 w-96 h-96 bg-secondary/10 rounded-full blur-3xl animate-pulse-slow pointer-events-none" style={{ animationDelay: '2s' }} />
      <div className="fixed top-1/2 left-1/2 w-64 h-64 bg-accent/5 rounded-full blur-3xl animate-float pointer-events-none" />

      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 glass border-b border-border/50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3 group">
              <motion.div
                whileHover={{ rotate: 360 }}
                transition={{ duration: 0.5 }}
                className="relative"
              >
                <Shield className="w-8 h-8 text-primary" />
                <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full" />
              </motion.div>
              <div>
                <h1 className="text-xl font-bold gradient-text">Solana Security</h1>
                <p className="text-xs text-text-secondary">Patterns & Best Practices</p>
              </div>
            </Link>

            <nav className="flex items-center gap-2">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = location.pathname === item.path;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-300 ${
                      isActive
                        ? 'bg-primary/20 text-primary border border-primary/30'
                        : 'text-text-secondary hover:text-text hover:bg-surface-light'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span className="text-sm font-medium">{item.label}</span>
                  </Link>
                );
              })}
              
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-text-secondary hover:text-text hover:bg-surface-light transition-all duration-300 ml-2"
              >
                <Github className="w-4 h-4" />
                <span className="text-sm font-medium">GitHub</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </nav>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="relative z-10 pt-24 pb-12">
        {children}
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-border/50 glass">
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              <span className="text-text-secondary text-sm">
                Solana Security Patterns — Educational Resource for Developers
              </span>
            </div>
            <div className="flex items-center gap-6 text-sm text-text-secondary">
              <a href="https://www.anchor-lang.com/docs" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors">
                Anchor Docs
              </a>
              <a href="https://solana.com/docs" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors">
                Solana Docs
              </a>
              <a href="https://github.com/anza-xyz/pinocchio" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors">
                Pinocchio
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;
