import React from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Code, BookOpen, Zap, Lock, Eye, Target } from 'lucide-react';
import PatternCard from '../components/PatternCard';
import { securityPatterns } from '../data/patterns';

const HomePage: React.FC = () => {
  const stats = [
    { label: 'Security Patterns', value: securityPatterns.length, icon: Shield },
    { label: 'Vulnerability Types', value: '6+', icon: AlertTriangle },
    { label: 'Code Examples', value: '12+', icon: Code },
    { label: 'Best Practices', value: '30+', icon: BookOpen },
  ];

  const features = [
    {
      icon: Eye,
      title: 'Side-by-Side Comparison',
      description: 'See vulnerable and secure code patterns directly compared with detailed explanations.',
    },
    {
      icon: Target,
      title: 'Real Attack Scenarios',
      description: 'Understand how attackers exploit vulnerabilities with realistic attack scenarios.',
    },
    {
      icon: Lock,
      title: 'Anchor & Pinocchio',
      description: 'Examples covering both Anchor framework and native Solana development patterns.',
    },
    {
      icon: Zap,
      title: 'Production Ready',
      description: 'Learn patterns used in production DeFi protocols and battle-tested applications.',
    },
  ];

  return (
    <div className="max-w-7xl mx-auto px-6">
      {/* Hero Section */}
      <section className="relative py-20 overflow-hidden">
        {/* Decorative elements */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-primary/20 via-primary/5 to-transparent rounded-full blur-3xl" />
        
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="relative text-center"
        >
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-8"
          >
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">Educational Security Resource</span>
          </motion.div>

          {/* Title */}
          <h1 className="text-5xl md:text-7xl font-bold mb-6">
            <span className="gradient-text">Solana Security</span>
            <br />
            <span className="text-text">Patterns & Best Practices</span>
          </h1>

          {/* Subtitle */}
          <p className="text-xl text-text-secondary max-w-3xl mx-auto mb-12 leading-relaxed">
            Learn to identify and prevent common vulnerabilities in Solana programs. 
            Each pattern shows <span className="text-error font-semibold">vulnerable</span> code 
            alongside its <span className="text-success font-semibold">secure</span> counterpart 
            with detailed explanations.
          </p>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
            {stats.map((stat, index) => {
              const Icon = stat.icon;
              return (
                <motion.div
                  key={stat.label}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 + index * 0.1 }}
                  className="p-6 rounded-2xl bg-surface/50 border border-border/50 hover:border-primary/30 transition-colors"
                >
                  <Icon className="w-6 h-6 text-primary mx-auto mb-3" />
                  <div className="text-3xl font-bold text-text mb-1">{stat.value}</div>
                  <div className="text-sm text-text-secondary">{stat.label}</div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>
      </section>

      {/* Features Section */}
      <section className="py-16">
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          className="grid md:grid-cols-2 lg:grid-cols-4 gap-6"
        >
          {features.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1 }}
                className="p-6 rounded-2xl bg-surface/30 border border-border/30 hover:border-primary/30 transition-all duration-300 group"
              >
                <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                  <Icon className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-lg font-semibold text-text mb-2">{feature.title}</h3>
                <p className="text-sm text-text-secondary leading-relaxed">{feature.description}</p>
              </motion.div>
            );
          })}
        </motion.div>
      </section>

      {/* Patterns Section */}
      <section className="py-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-text mb-4">
            Security Patterns
          </h2>
          <p className="text-text-secondary max-w-2xl mx-auto">
            Explore common vulnerabilities and learn how to write secure Solana programs. 
            Each pattern includes vulnerable code, secure alternatives, and detailed explanations.
          </p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {securityPatterns.map((pattern, index) => (
            <PatternCard
              key={pattern.id}
              id={pattern.id}
              title={pattern.title}
              description={pattern.description}
              severity={pattern.severity}
              category={pattern.category}
              index={index}
            />
          ))}
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="relative p-12 rounded-3xl bg-gradient-to-br from-primary/10 via-surface to-secondary/10 border border-primary/20 overflow-hidden"
        >
          {/* Background decoration */}
          <div className="absolute top-0 right-0 w-64 h-64 bg-primary/10 rounded-full blur-3xl" />
          <div className="absolute bottom-0 left-0 w-48 h-48 bg-secondary/10 rounded-full blur-3xl" />
          
          <div className="relative text-center">
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-4">
              Ready to Secure Your Programs?
            </h2>
            <p className="text-text-secondary max-w-2xl mx-auto mb-8">
              Dive deep into each security pattern, understand the vulnerabilities, 
              and implement battle-tested solutions in your Solana programs.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <a
                href="/deep-dive"
                className="px-8 py-4 rounded-xl bg-gradient-to-r from-primary to-secondary text-white font-semibold hover:opacity-90 transition-opacity flex items-center gap-2"
              >
                <BookOpen className="w-5 h-5" />
                Read Deep Dive
              </a>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="px-8 py-4 rounded-xl bg-surface border border-border hover:border-primary/50 text-text font-semibold transition-colors flex items-center gap-2"
              >
                <Code className="w-5 h-5" />
                View on GitHub
              </a>
            </div>
          </div>
        </motion.div>
      </section>
    </div>
  );
};

export default HomePage;
