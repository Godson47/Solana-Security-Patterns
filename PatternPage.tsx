import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  ArrowLeft, 
  AlertTriangle, 
  Shield, 
  BookOpen, 
  Target, 
  CheckCircle,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import CodeBlock from '../components/CodeBlock';
import { getPatternById, securityPatterns } from '../data/patterns';

const PatternPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const pattern = getPatternById(id || '');

  if (!pattern) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-20 text-center">
        <h1 className="text-2xl font-bold text-text mb-4">Pattern Not Found</h1>
        <p className="text-text-secondary mb-8">The security pattern you're looking for doesn't exist.</p>
        <Link to="/" className="text-primary hover:underline">
          ← Back to all patterns
        </Link>
      </div>
    );
  }

  const severityColors = {
    critical: 'bg-error/20 text-error border-error/30',
    high: 'bg-warning/20 text-warning border-warning/30',
    medium: 'bg-secondary/20 text-secondary border-secondary/30',
  };

  const currentIndex = securityPatterns.findIndex(p => p.id === id);
  const nextPattern = securityPatterns[currentIndex + 1];
  const prevPattern = securityPatterns[currentIndex - 1];

  return (
    <div className="max-w-6xl mx-auto px-6">
      {/* Back button */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="mb-8"
      >
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-text-secondary hover:text-primary transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to all patterns</span>
        </Link>
      </motion.div>

      {/* Header */}
      <motion.header
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-12"
      >
        <div className="flex flex-wrap items-center gap-4 mb-4">
          <span className="px-3 py-1 rounded-lg bg-primary/10 text-primary text-sm font-medium">
            {pattern.category}
          </span>
          <span className={`px-3 py-1 rounded-lg text-sm font-bold border ${severityColors[pattern.severity]}`}>
            {pattern.severity.toUpperCase()} SEVERITY
          </span>
        </div>
        
        <h1 className="text-4xl md:text-5xl font-bold text-text mb-4">
          {pattern.title}
        </h1>
        
        <p className="text-xl text-text-secondary leading-relaxed">
          {pattern.description}
        </p>
      </motion.header>

      {/* Overview */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="mb-12"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-lg bg-primary/10">
            <BookOpen className="w-5 h-5 text-primary" />
          </div>
          <h2 className="text-2xl font-bold text-text">Overview</h2>
        </div>
        
        <div className="p-6 rounded-2xl bg-surface/50 border border-border/50">
          <div className="prose prose-invert max-w-none">
            {pattern.explanation.split('\n').map((paragraph, i) => (
              paragraph.trim() && (
                <p key={i} className="text-text-secondary leading-relaxed mb-4 last:mb-0">
                  {paragraph}
                </p>
              )
            ))}
          </div>
        </div>
      </motion.section>

      {/* Code Comparison */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="mb-12"
      >
        <h2 className="text-2xl font-bold text-text mb-6">Code Comparison</h2>
        
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Vulnerable Code */}
          <div>
            <CodeBlock
              code={pattern.vulnerableCode}
              language="rust"
              title="vulnerable.rs"
              variant="vulnerable"
            />
            
            <div className="mt-4 p-4 rounded-xl bg-error/5 border border-error/20">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-5 h-5 text-error" />
                <h3 className="font-semibold text-error">What's Wrong</h3>
              </div>
              <div className="text-sm text-text-secondary space-y-2">
                {pattern.vulnerableExplanation.split('\n').map((line, i) => (
                  line.trim() && (
                    <p key={i}>{line}</p>
                  )
                ))}
              </div>
            </div>
          </div>

          {/* Secure Code */}
          <div>
            <CodeBlock
              code={pattern.secureCode}
              language="rust"
              title="secure.rs"
              variant="secure"
            />
            
            <div className="mt-4 p-4 rounded-xl bg-success/5 border border-success/20">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-5 h-5 text-success" />
                <h3 className="font-semibold text-success">Security Measures</h3>
              </div>
              <div className="text-sm text-text-secondary space-y-2">
                {pattern.secureExplanation.split('\n').map((line, i) => (
                  line.trim() && (
                    <p key={i}>{line}</p>
                  )
                ))}
              </div>
            </div>
          </div>
        </div>
      </motion.section>

      {/* Attack Scenario */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="mb-12"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-lg bg-error/10">
            <Target className="w-5 h-5 text-error" />
          </div>
          <h2 className="text-2xl font-bold text-text">Attack Scenario</h2>
        </div>
        
        <div className="p-6 rounded-2xl bg-surface/50 border border-error/20">
          <div className="text-text-secondary space-y-3">
            {pattern.attackScenario.split('\n').map((line, i) => (
              line.trim() && (
                <p key={i} className={line.startsWith('**') ? 'font-semibold text-text' : ''}>
                  {line.replace(/\*\*/g, '')}
                </p>
              )
            ))}
          </div>
        </div>
      </motion.section>

      {/* Prevention */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="mb-12"
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-lg bg-success/10">
            <CheckCircle className="w-5 h-5 text-success" />
          </div>
          <h2 className="text-2xl font-bold text-text">Prevention Checklist</h2>
        </div>
        
        <div className="grid md:grid-cols-2 gap-4">
          {pattern.prevention.map((item, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.5 + index * 0.05 }}
              className="flex items-start gap-3 p-4 rounded-xl bg-surface/30 border border-border/30"
            >
              <CheckCircle className="w-5 h-5 text-success flex-shrink-0 mt-0.5" />
              <span className="text-text-secondary">{item}</span>
            </motion.div>
          ))}
        </div>
      </motion.section>

      {/* References */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="mb-12"
      >
        <h2 className="text-2xl font-bold text-text mb-6">References</h2>
        
        <div className="flex flex-wrap gap-4">
          {pattern.references.map((ref, index) => (
            <a
              key={index}
              href={ref.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-3 rounded-xl bg-surface/50 border border-border/50 hover:border-primary/50 transition-colors group"
            >
              <span className="text-text-secondary group-hover:text-text transition-colors">
                {ref.title}
              </span>
              <ExternalLink className="w-4 h-4 text-text-secondary group-hover:text-primary transition-colors" />
            </a>
          ))}
        </div>
      </motion.section>

      {/* Navigation */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="py-8 border-t border-border/50"
      >
        <div className="flex justify-between items-center">
          {prevPattern ? (
            <Link
              to={`/pattern/${prevPattern.id}`}
              className="flex items-center gap-3 p-4 rounded-xl bg-surface/30 border border-border/30 hover:border-primary/50 transition-colors group"
            >
              <ArrowLeft className="w-5 h-5 text-text-secondary group-hover:text-primary transition-colors" />
              <div>
                <div className="text-xs text-text-secondary">Previous</div>
                <div className="text-text font-medium">{prevPattern.title}</div>
              </div>
            </Link>
          ) : (
            <div />
          )}
          
          {nextPattern && (
            <Link
              to={`/pattern/${nextPattern.id}`}
              className="flex items-center gap-3 p-4 rounded-xl bg-surface/30 border border-border/30 hover:border-primary/50 transition-colors group text-right"
            >
              <div>
                <div className="text-xs text-text-secondary">Next</div>
                <div className="text-text font-medium">{nextPattern.title}</div>
              </div>
              <ChevronRight className="w-5 h-5 text-text-secondary group-hover:text-primary transition-colors" />
            </Link>
          )}
        </div>
      </motion.section>
    </div>
  );
};

export default PatternPage;
