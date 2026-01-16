import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { AlertTriangle, Shield, ArrowRight, Code } from 'lucide-react';

interface PatternCardProps {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
  category: string;
  index: number;
}

const PatternCard: React.FC<PatternCardProps> = ({
  id,
  title,
  description,
  severity,
  category,
  index,
}) => {
  const severityColors = {
    critical: 'bg-error/20 text-error border-error/30',
    high: 'bg-warning/20 text-warning border-warning/30',
    medium: 'bg-secondary/20 text-secondary border-secondary/30',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1 }}
      whileHover={{ y: -5, scale: 1.02 }}
      className="group"
    >
      <Link to={`/pattern/${id}`}>
        <div className="relative h-full p-6 rounded-2xl bg-surface/50 border border-border/50 hover:border-primary/50 transition-all duration-300 overflow-hidden">
          {/* Background glow on hover */}
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
          
          {/* Content */}
          <div className="relative z-10">
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                  <Code className="w-5 h-5 text-primary" />
                </div>
                <span className="text-xs font-medium text-text-secondary uppercase tracking-wider">
                  {category}
                </span>
              </div>
              <span className={`px-2 py-1 rounded-md text-xs font-bold border ${severityColors[severity]}`}>
                {severity.toUpperCase()}
              </span>
            </div>

            {/* Title */}
            <h3 className="text-xl font-bold text-text mb-3 group-hover:text-primary transition-colors">
              {title}
            </h3>

            {/* Description */}
            <p className="text-text-secondary text-sm leading-relaxed mb-6">
              {description}
            </p>

            {/* Footer */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-1.5 text-error">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-xs font-medium">Vulnerable</span>
                </div>
                <div className="flex items-center gap-1.5 text-success">
                  <Shield className="w-4 h-4" />
                  <span className="text-xs font-medium">Secure</span>
                </div>
              </div>
              <div className="flex items-center gap-2 text-primary opacity-0 group-hover:opacity-100 transition-opacity">
                <span className="text-sm font-medium">View Pattern</span>
                <ArrowRight className="w-4 h-4" />
              </div>
            </div>
          </div>

          {/* Decorative corner */}
          <div className="absolute -bottom-2 -right-2 w-24 h-24 bg-gradient-to-tl from-primary/10 to-transparent rounded-tl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
        </div>
      </Link>
    </motion.div>
  );
};

export default PatternCard;
