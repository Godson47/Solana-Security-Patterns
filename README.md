# Solana Security Patterns - Smart Contracts

This directory contains the smart contract examples demonstrating vulnerable vs secure patterns for Solana program development.

## Structure

Each vulnerability pattern has two versions:
- `vulnerable_*.rs` - The insecure implementation with detailed comments explaining the vulnerability
- `secure_*.rs` - The fixed implementation with security measures explained

## Patterns Included

### 1. Missing Signer Verification (`signer_check/`)
- **Vulnerability**: Not verifying that critical accounts have signed the transaction
- **Impact**: Unauthorized actions, fund theft
- **Severity**: Critical

### 2. Missing Owner Verification (`owner_check/`)
- **Vulnerability**: Not verifying account ownership before reading data
- **Impact**: Fake account injection, data manipulation
- **Severity**: Critical

### 3. Integer Overflow/Underflow (`arithmetic/`)
- **Vulnerability**: Unchecked arithmetic operations
- **Impact**: Balance manipulation, fund theft
- **Severity**: Critical

### 4. PDA Seed Collision (`pda_security/`)
- **Vulnerability**: Predictable or insufficient PDA seeds
- **Impact**: Account collision, unauthorized access
- **Severity**: High

### 5. Unsafe CPI (`cpi_security/`)
- **Vulnerability**: Improper cross-program invocation handling
- **Impact**: Reentrancy, privilege escalation
- **Severity**: Critical

### 6. Account Data Matching (`account_matching/`)
- **Vulnerability**: Not verifying relationships between accounts
- **Impact**: Account substitution, fund theft
- **Severity**: High

## Building

```bash
# Install Anchor CLI
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --locked

# Build all programs
anchor build

# Run tests
anchor test
```

## Testing

Each pattern includes tests that demonstrate:
1. The vulnerability being exploited
2. The secure version preventing the exploit

```bash
# Run specific pattern tests
anchor test --skip-local-validator tests/signer_check.ts
```

## Usage

These contracts are for **educational purposes only**. Do not deploy vulnerable versions to any network.

When studying:
1. Read the vulnerable code first
2. Understand the attack vector
3. Study the secure implementation
4. Run the tests to see the difference

## Contributing

To add a new security pattern:
1. Create a new directory under `contracts/`
2. Add `vulnerable_*.rs` and `secure_*.rs`
3. Include comprehensive comments
4. Add tests demonstrating the vulnerability
5. Update this README

## Resources

- [Anchor Documentation](https://www.anchor-lang.com/docs)
- [Solana Security Best Practices](https://solana.com/docs/programs/security)
- [Solana Account Model](https://solana.com/docs/core/accounts)
