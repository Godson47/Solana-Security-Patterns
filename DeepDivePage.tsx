import React from 'react';
import { motion } from 'framer-motion';
import { 
  BookOpen, 
  Shield, 
  AlertTriangle, 
  Code, 
  Zap,
  Lock,
  Eye,
  Target,
  CheckCircle,
  ArrowRight
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { securityPatterns } from '../data/patterns';

const DeepDivePage: React.FC = () => {
  const sections = [
    {
      id: 'introduction',
      title: 'Introduction',
      icon: BookOpen,
      content: `
Security remains one of the biggest challenges in Solana program development. Many exploits do not come from complex attacks, but from simple mistakes: missing account validation, incorrect authority checks, unsafe arithmetic, or misunderstood CPI behavior.

Anchor and Pinocchio provide strong abstractions, but they do not automatically make programs safe. Developers still need to understand why a pattern is dangerous and how to fix it correctly.

This resource focuses on building a clear, educational security reference for Solana developers by contrasting vulnerable code with secure alternatives. The goal is to make security concepts practical and obvious, especially for developers learning Anchor or Pinocchio.
      `,
    },
    {
      id: 'account-model',
      title: 'Understanding Solana\'s Account Model',
      icon: Eye,
      content: `
Before diving into vulnerabilities, it's crucial to understand Solana's account model:

**Key Concepts:**
- Every piece of data on Solana lives in an "account"
- Accounts have an "owner" program that controls modifications
- Programs are stateless - they read/write to accounts
- Transactions specify which accounts to use

**Security Implications:**
- Programs must verify accounts are what they claim to be
- The owner field determines who can modify account data
- Signers must be verified for authorization
- PDAs provide deterministic, program-controlled addresses

**Common Misconceptions:**
- "Anchor handles all security" - FALSE, you must still validate
- "If it compiles, it's safe" - FALSE, logic errors aren't caught
- "PDAs are always secure" - FALSE, seeds must be carefully chosen
      `,
    },
    {
      id: 'vulnerability-categories',
      title: 'Vulnerability Categories',
      icon: AlertTriangle,
      content: `
Solana vulnerabilities generally fall into these categories:

**1. Account Validation Failures**
- Missing signer checks
- Missing owner verification
- Incorrect PDA derivation
- Account data type confusion

**2. Arithmetic Issues**
- Integer overflow/underflow
- Precision loss in calculations
- Incorrect decimal handling

**3. Access Control Failures**
- Missing authority checks
- Incorrect permission logic
- Privilege escalation

**4. Cross-Program Invocation (CPI) Issues**
- Calling unverified programs
- Reentrancy vulnerabilities
- Incorrect signer propagation

**5. State Management Issues**
- Race conditions
- Stale data usage
- Incomplete state updates

**6. Economic/Logic Vulnerabilities**
- Price manipulation
- Flash loan attacks
- Sandwich attacks
      `,
    },
    {
      id: 'anchor-security',
      title: 'Anchor Security Features',
      icon: Shield,
      content: `
Anchor provides several security features, but understanding their limitations is crucial:

**Account Types:**
- \`Signer<'info>\` - Verifies account signed the transaction
- \`Account<'info, T>\` - Deserializes and validates account type
- \`Program<'info, T>\` - Verifies program ID matches expected

**Constraints:**
- \`#[account(mut)]\` - Marks account as mutable
- \`#[account(has_one = field)]\` - Verifies field matches
- \`#[account(seeds = [...], bump)]\` - Verifies PDA derivation
- \`#[account(owner = program_id)]\` - Verifies account owner

**What Anchor DOESN'T Do:**
- Validate business logic
- Prevent arithmetic overflow (in release mode)
- Verify relationships between accounts automatically
- Protect against reentrancy
- Validate external program behavior
      `,
    },
    {
      id: 'best-practices',
      title: 'Security Best Practices',
      icon: CheckCircle,
      content: `
Follow these practices to write secure Solana programs:

**1. Validate Everything**
- Every account should have explicit validation
- Use constraints liberally
- Verify relationships between accounts

**2. Use Checked Arithmetic**
- Always use checked_add, checked_sub, checked_mul
- Consider using u128 for intermediate calculations
- Validate bounds before and after operations

**3. Follow CEI Pattern**
- Checks: Validate all inputs and state
- Effects: Update state
- Interactions: Make external calls last

**4. Minimize Trust**
- Don't trust account data without verification
- Verify program IDs for CPI
- Use PDAs for program-controlled accounts

**5. Test Thoroughly**
- Write tests for edge cases
- Test with malicious inputs
- Simulate attack scenarios

**6. Audit and Review**
- Get external security audits
- Use static analysis tools
- Review code changes carefully
      `,
    },
    {
      id: 'testing-security',
      title: 'Testing for Security',
      icon: Target,
      content: `
Effective security testing requires thinking like an attacker:

**Test Categories:**

1. **Input Validation Tests**
   - Pass zero values
   - Pass maximum values
   - Pass invalid account types

2. **Authorization Tests**
   - Call without required signers
   - Call with wrong authority
   - Test permission boundaries

3. **State Manipulation Tests**
   - Test with stale state
   - Test concurrent operations
   - Test partial state updates

4. **Economic Tests**
   - Test with extreme prices
   - Test rounding behavior
   - Test fee calculations

**Testing Tools:**
- Anchor's testing framework
- Bankrun for fast local testing
- Trident for fuzzing
- Custom attack simulations
      `,
    },
  ];

  return (
    <div className="max-w-4xl mx-auto px-6">
      {/* Header */}
      <motion.header
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center py-16"
      >
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
          <BookOpen className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium text-primary">Deep Dive</span>
        </div>
        
        <h1 className="text-4xl md:text-5xl font-bold mb-6">
          <span className="gradient-text">Solana Security</span>
          <br />
          <span className="text-text">Complete Guide</span>
        </h1>
        
        <p className="text-xl text-text-secondary max-w-2xl mx-auto">
          A comprehensive guide to understanding and preventing security vulnerabilities 
          in Solana programs. Learn the patterns that protect millions in DeFi.
        </p>
      </motion.header>

      {/* Table of Contents */}
      <motion.nav
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="mb-16 p-6 rounded-2xl bg-surface/50 border border-border/50"
      >
        <h2 className="text-lg font-semibold text-text mb-4">Table of Contents</h2>
        <div className="grid md:grid-cols-2 gap-2">
          {sections.map((section, index) => {
            const Icon = section.icon;
            return (
              <a
                key={section.id}
                href={`#${section.id}`}
                className="flex items-center gap-3 p-3 rounded-lg hover:bg-surface-light transition-colors group"
              >
                <span className="text-text-secondary">{index + 1}.</span>
                <Icon className="w-4 h-4 text-primary" />
                <span className="text-text-secondary group-hover:text-text transition-colors">
                  {section.title}
                </span>
              </a>
            );
          })}
        </div>
      </motion.nav>

      {/* Sections */}
      {sections.map((section, index) => {
        const Icon = section.icon;
        return (
          <motion.section
            key={section.id}
            id={section.id}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="mb-16"
          >
            <div className="flex items-center gap-4 mb-6">
              <div className="p-3 rounded-xl bg-primary/10 border border-primary/20">
                <Icon className="w-6 h-6 text-primary" />
              </div>
              <div>
                <span className="text-sm text-text-secondary">Section {index + 1}</span>
                <h2 className="text-2xl font-bold text-text">{section.title}</h2>
              </div>
            </div>
            
            <div className="p-6 rounded-2xl bg-surface/30 border border-border/30">
              <div className="prose prose-invert max-w-none">
                {section.content.split('\n').map((paragraph, i) => {
                  if (paragraph.trim().startsWith('**') && paragraph.trim().endsWith('**')) {
                    return (
                      <h3 key={i} className="text-lg font-semibold text-text mt-6 mb-3">
                        {paragraph.replace(/\*\*/g, '')}
                      </h3>
                    );
                  }
                  if (paragraph.trim().startsWith('- ')) {
                    return (
                      <li key={i} className="text-text-secondary ml-4 mb-1">
                        {paragraph.replace('- ', '')}
                      </li>
                    );
                  }
                  if (paragraph.trim().match(/^\d+\./)) {
                    return (
                      <li key={i} className="text-text-secondary ml-4 mb-1 list-decimal">
                        {paragraph.replace(/^\d+\.\s*/, '')}
                      </li>
                    );
                  }
                  return paragraph.trim() && (
                    <p key={i} className="text-text-secondary leading-relaxed mb-4">
                      {paragraph}
                    </p>
                  );
                })}
              </div>
            </div>
          </motion.section>
        );
      })}

      {/* Patterns CTA */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="mb-16"
      >
        <div className="p-8 rounded-2xl bg-gradient-to-br from-primary/10 via-surface to-secondary/10 border border-primary/20">
          <h2 className="text-2xl font-bold text-text mb-4">
            Explore Security Patterns
          </h2>
          <p className="text-text-secondary mb-6">
            Now that you understand the theory, explore our {securityPatterns.length} detailed 
            security patterns with vulnerable and secure code examples.
          </p>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {securityPatterns.slice(0, 3).map((pattern) => (
              <Link
                key={pattern.id}
                to={`/pattern/${pattern.id}`}
                className="p-4 rounded-xl bg-surface/50 border border-border/50 hover:border-primary/50 transition-colors group"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-text-secondary">{pattern.category}</span>
                  <ArrowRight className="w-4 h-4 text-text-secondary group-hover:text-primary transition-colors" />
                </div>
                <h3 className="font-semibold text-text group-hover:text-primary transition-colors">
                  {pattern.title}
                </h3>
              </Link>
            ))}
          </div>
          
          <Link
            to="/"
            className="inline-flex items-center gap-2 mt-6 text-primary hover:underline"
          >
            View all patterns
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </motion.section>

      {/* Resources */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="mb-16"
      >
        <h2 className="text-2xl font-bold text-text mb-6">Additional Resources</h2>
        
        <div className="grid md:grid-cols-2 gap-4">
          {[
            { title: 'Anchor Documentation', url: 'https://www.anchor-lang.com/docs', desc: 'Official Anchor framework docs' },
            { title: 'Solana Documentation', url: 'https://solana.com/docs', desc: 'Core Solana concepts and APIs' },
            { title: 'Pinocchio Framework', url: 'https://github.com/anza-xyz/pinocchio', desc: 'Native Solana development' },
            { title: 'Solana Account Model', url: 'https://solana.com/docs/core/accounts', desc: 'Deep dive into accounts' },
          ].map((resource) => (
            <a
              key={resource.url}
              href={resource.url}
              target="_blank"
              rel="noopener noreferrer"
              className="p-4 rounded-xl bg-surface/30 border border-border/30 hover:border-primary/50 transition-colors group"
            >
              <h3 className="font-semibold text-text group-hover:text-primary transition-colors mb-1">
                {resource.title}
              </h3>
              <p className="text-sm text-text-secondary">{resource.desc}</p>
            </a>
          ))}
        </div>
      </motion.section>
    </div>
  );
};

export default DeepDivePage;
