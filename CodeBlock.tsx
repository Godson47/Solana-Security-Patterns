import React, { useState } from 'react';
import { Highlight, themes } from 'prism-react-renderer';
import { motion } from 'framer-motion';
import { Copy, Check, AlertTriangle, Shield } from 'lucide-react';

interface CodeBlockProps {
  code: string;
  language?: string;
  title?: string;
  variant?: 'vulnerable' | 'secure' | 'neutral';
  showLineNumbers?: boolean;
}

const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  language = 'rust',
  title,
  variant = 'neutral',
  showLineNumbers = true,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const variantStyles = {
    vulnerable: {
      border: 'border-error/30',
      bg: 'bg-error/5',
      icon: AlertTriangle,
      iconColor: 'text-error',
      label: 'VULNERABLE',
      labelBg: 'bg-error/20',
      glow: 'glow-error',
    },
    secure: {
      border: 'border-success/30',
      bg: 'bg-success/5',
      icon: Shield,
      iconColor: 'text-success',
      label: 'SECURE',
      labelBg: 'bg-success/20',
      glow: 'glow-success',
    },
    neutral: {
      border: 'border-border',
      bg: 'bg-surface',
      icon: null,
      iconColor: '',
      label: '',
      labelBg: '',
      glow: '',
    },
  };

  const style = variantStyles[variant];
  const Icon = style.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-xl overflow-hidden ${style.border} border ${style.bg} ${variant !== 'neutral' ? style.glow : ''}`}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-surface-light/50 border-b border-border/50">
        <div className="flex items-center gap-3">
          {Icon && (
            <div className={`flex items-center gap-2 px-2 py-1 rounded-md ${style.labelBg}`}>
              <Icon className={`w-4 h-4 ${style.iconColor}`} />
              <span className={`text-xs font-bold ${style.iconColor}`}>{style.label}</span>
            </div>
          )}
          {title && (
            <span className="text-sm text-text-secondary font-mono">{title}</span>
          )}
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-light transition-colors text-text-secondary hover:text-text"
        >
          {copied ? (
            <>
              <Check className="w-4 h-4 text-success" />
              <span className="text-xs">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-4 h-4" />
              <span className="text-xs">Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Code */}
      <Highlight theme={themes.nightOwl} code={code.trim()} language={language as any}>
        {({ className, style: highlightStyle, tokens, getLineProps, getTokenProps }) => (
          <pre
            className={`${className} code-block p-4 overflow-x-auto`}
            style={{ ...highlightStyle, background: 'transparent' }}
          >
            {tokens.map((line, i) => (
              <div key={i} {...getLineProps({ line })} className="table-row">
                {showLineNumbers && (
                  <span className="table-cell pr-4 text-text-secondary/40 select-none text-right w-8">
                    {i + 1}
                  </span>
                )}
                <span className="table-cell">
                  {line.map((token, key) => (
                    <span key={key} {...getTokenProps({ token })} />
                  ))}
                </span>
              </div>
            ))}
          </pre>
        )}
      </Highlight>
    </motion.div>
  );
};

export default CodeBlock;
