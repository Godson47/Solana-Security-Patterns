export interface SecurityPattern {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
  category: string;
  explanation: string;
  vulnerableCode: string;
  secureCode: string;
  vulnerableExplanation: string;
  secureExplanation: string;
  attackScenario: string;
  prevention: string[];
  references: { title: string; url: string }[];
}

export const securityPatterns: SecurityPattern[] = [
  {
    id: 'missing-signer-check',
    title: 'Missing Signer Verification',
    description: 'Failing to verify that critical accounts have signed the transaction, allowing unauthorized actions.',
    severity: 'critical',
    category: 'Account Validation',
    explanation: `
One of the most fundamental security checks in Solana programs is verifying that accounts have actually signed the transaction. Without this check, anyone can pass any public key as an "authority" account and perform unauthorized actions.

In Solana's account model, each account in a transaction has an \`is_signer\` flag that indicates whether the account's private key was used to sign the transaction. Programs MUST check this flag for any account that should have authority over an action.

This vulnerability is particularly dangerous because:
1. It allows complete bypass of access control
2. Attackers can drain funds, modify state, or take ownership
3. The exploit is trivial to execute once discovered
    `,
    vulnerableCode: `use anchor_lang::prelude::*;

declare_id!("Vuln111111111111111111111111111111111111111");

#[program]
pub mod vulnerable_signer {
    use super::*;

    // ❌ VULNERABLE: No signer verification!
    // Anyone can call this and pass ANY pubkey as authority
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // This will succeed even if 'authority' didn't sign!
        let vault = &mut ctx.accounts.vault;
        
        // Attacker can pass victim's pubkey as authority
        // and drain their vault without their signature
        vault.balance = vault.balance.checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        
        // Transfer funds to attacker...
        msg!("Withdrew {} lamports", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // ❌ VULNERABLE: No Signer constraint!
    // This account is NOT required to sign the transaction
    /// CHECK: This should be the vault authority but isn't verified
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
}`,
    secureCode: `use anchor_lang::prelude::*;

declare_id!("Secure1111111111111111111111111111111111111");

#[program]
pub mod secure_signer {
    use super::*;

    // ✅ SECURE: Proper signer verification
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Additional check: verify authority matches vault's stored authority
        // This is defense-in-depth alongside the Signer constraint
        require_keys_eq!(
            ctx.accounts.authority.key(),
            vault.authority,
            ErrorCode::UnauthorizedAuthority
        );
        
        vault.balance = vault.balance.checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        
        msg!("Withdrew {} lamports", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // ✅ SECURE: Signer constraint ensures this account signed the tx
    // The transaction will fail if authority didn't sign
    #[account(
        constraint = authority.key() == vault.authority @ ErrorCode::UnauthorizedAuthority
    )]
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Unauthorized authority for this vault")]
    UnauthorizedAuthority,
}`,
    vulnerableExplanation: `
**What's Wrong:**
- The \`authority\` account uses \`AccountInfo<'info>\` with no constraints
- There's no \`Signer\` type or \`is_signer\` check
- Anyone can pass any public key as the authority
- The program blindly trusts the passed account

**Attack Vector:**
1. Attacker finds a vault with funds
2. Attacker creates a transaction passing the victim's pubkey as authority
3. Since no signature is required, the transaction succeeds
4. Attacker drains the vault
    `,
    secureExplanation: `
**Security Measures:**
1. **Signer<'info> type**: Anchor automatically verifies the account signed the transaction
2. **Constraint check**: Verifies the signer matches the vault's stored authority
3. **Custom error**: Provides clear feedback on authorization failures

**Why This Works:**
- Solana runtime enforces that Signer accounts must have signed
- The constraint provides defense-in-depth
- Even if an attacker knows the authority pubkey, they can't sign without the private key
    `,
    attackScenario: `
**Real-World Attack Scenario:**

1. A DeFi protocol has a vault system where users deposit funds
2. The withdraw function doesn't verify signers
3. Attacker scans the blockchain for vaults with significant balances
4. For each vault, attacker:
   - Reads the vault's authority pubkey from account data
   - Constructs a withdraw transaction with that pubkey
   - Signs only with their own keypair (not the authority)
   - Submits the transaction
5. All vaults are drained in minutes

**Historical Example:** This exact vulnerability has led to millions in losses across various Solana protocols.
    `,
    prevention: [
      'Always use Signer<\'info> for accounts that must authorize actions',
      'Add constraint checks to verify the signer matches stored authority',
      'Use Anchor\'s has_one constraint for automatic authority matching',
      'Implement defense-in-depth with multiple validation layers',
      'Audit all instruction handlers for missing signer checks',
    ],
    references: [
      { title: 'Anchor Signer Documentation', url: 'https://www.anchor-lang.com/docs/account-types#signer' },
      { title: 'Solana Account Model', url: 'https://solana.com/docs/core/accounts' },
    ],
  },
  {
    id: 'missing-owner-check',
    title: 'Missing Account Owner Verification',
    description: 'Not verifying that an account is owned by the expected program, allowing fake account injection.',
    severity: 'critical',
    category: 'Account Validation',
    explanation: `
Every account on Solana has an "owner" field that indicates which program has write access to it. When your program reads data from an account, you MUST verify the account is owned by the expected program.

Without owner verification, an attacker can:
1. Create a fake account with malicious data
2. Set themselves as the owner
3. Pass this fake account to your program
4. Your program reads the fake data as if it were legitimate

This is especially dangerous when reading token accounts, PDAs, or any account your program didn't create in the same transaction.
    `,
    vulnerableCode: `use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;

declare_id!("Vuln222222222222222222222222222222222222222");

#[program]
pub mod vulnerable_owner {
    use super::*;

    // ❌ VULNERABLE: No owner verification on price feed
    pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
        // Reading price from unverified account!
        // Attacker can pass a fake account with manipulated price
        let price_data = ctx.accounts.price_feed.try_borrow_data()?;
        let price = u64::from_le_bytes(
            price_data[0..8].try_into().unwrap()
        );
        
        // Calculate output based on potentially fake price
        let amount_out = amount_in
            .checked_mul(price)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(1_000_000)
            .ok_or(ErrorCode::MathOverflow)?;
        
        msg!("Swapping {} for {} at price {}", amount_in, amount_out, price);
        
        // Transfer would happen here...
        // Attacker gets way more tokens than they should!
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_token_in: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_out: Account<'info, TokenAccount>,
    
    // ❌ VULNERABLE: No owner check!
    // Anyone can create an account with fake price data
    /// CHECK: Should be verified but isn't
    pub price_feed: AccountInfo<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Math overflow")]
    MathOverflow,
}`,
    secureCode: `use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;

declare_id!("Secure2222222222222222222222222222222222222");

// Define the expected oracle program ID
pub const ORACLE_PROGRAM_ID: Pubkey = pubkey!("Oracle11111111111111111111111111111111111");

#[program]
pub mod secure_owner {
    use super::*;

    // ✅ SECURE: Proper owner verification
    pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
        // Now we can trust the price data because we verified the owner
        let price_data = ctx.accounts.price_feed.try_borrow_data()?;
        let price = u64::from_le_bytes(
            price_data[0..8].try_into().unwrap()
        );
        
        // Additional validation: check price is within reasonable bounds
        require!(
            price > 0 && price < 1_000_000_000_000,
            ErrorCode::InvalidPrice
        );
        
        let amount_out = amount_in
            .checked_mul(price)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(1_000_000)
            .ok_or(ErrorCode::MathOverflow)?;
        
        msg!("Swapping {} for {} at verified price {}", amount_in, amount_out, price);
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_token_in: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_out: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Owner constraint verifies the account is owned by oracle
    // Attacker cannot create fake accounts owned by the oracle program
    #[account(
        owner = ORACLE_PROGRAM_ID @ ErrorCode::InvalidPriceFeedOwner
    )]
    /// CHECK: Owner is verified to be the oracle program
    pub price_feed: AccountInfo<'info>,
    
    // Alternative: Use a typed account if you control the oracle
    // #[account(
    //     has_one = oracle_authority,
    //     owner = crate::ID
    // )]
    // pub price_feed: Account<'info, PriceFeed>,
}

#[account]
pub struct PriceFeed {
    pub oracle_authority: Pubkey,
    pub price: u64,
    pub last_update: i64,
    pub confidence: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Invalid price feed owner")]
    InvalidPriceFeedOwner,
    #[msg("Price is invalid or out of bounds")]
    InvalidPrice,
}`,
    vulnerableExplanation: `
**What's Wrong:**
- The \`price_feed\` account has no owner verification
- Uses raw \`AccountInfo\` without constraints
- Attacker can create their own account with fake price data
- Program reads and trusts this manipulated data

**Attack Vector:**
1. Attacker creates an account they own
2. Writes fake price data (e.g., 1000x the real price)
3. Passes this fake account as the price feed
4. Program calculates swap based on fake price
5. Attacker receives 1000x more tokens than they should
    `,
    secureExplanation: `
**Security Measures:**
1. **Owner constraint**: Verifies account is owned by the oracle program
2. **Price bounds check**: Additional validation for reasonable values
3. **Custom error**: Clear feedback on validation failures

**Why This Works:**
- Only the oracle program can create accounts it owns
- Attacker cannot forge the owner field
- Even if attacker finds a bug in the oracle, bounds checking provides defense
    `,
    attackScenario: `
**Real-World Attack Scenario:**

1. A DEX uses an oracle for price feeds
2. The swap function doesn't verify the price feed owner
3. Attacker:
   - Creates a new account with their keypair
   - Writes data: price = 1,000,000 (1000x real price)
   - Calls swap with 1 token in, fake price feed
   - Receives 1000 tokens out instead of 1
4. Attacker repeats until pool is drained

**Impact:** This vulnerability has caused millions in losses in DeFi protocols.
    `,
    prevention: [
      'Always verify account owners using owner constraint',
      'Use typed Account<\'info, T> when possible for automatic owner checks',
      'Validate data bounds even after owner verification',
      'Use PDAs derived from your program for trusted accounts',
      'Document expected owners in account structs',
    ],
    references: [
      { title: 'Anchor Owner Constraint', url: 'https://www.anchor-lang.com/docs/account-constraints' },
      { title: 'Solana Account Ownership', url: 'https://solana.com/docs/core/accounts#ownership' },
    ],
  },
  {
    id: 'integer-overflow',
    title: 'Integer Overflow/Underflow',
    description: 'Arithmetic operations that can wrap around, leading to unexpected values and fund theft.',
    severity: 'critical',
    category: 'Arithmetic Safety',
    explanation: `
Integer overflow occurs when an arithmetic operation produces a value larger than the maximum the type can hold. In Rust, this behavior depends on the build mode:

- **Debug mode**: Panics on overflow (safe but crashes)
- **Release mode**: Wraps around silently (DANGEROUS!)

Since Solana programs run in release mode, unchecked arithmetic can lead to:
- Balances wrapping from max to 0 or vice versa
- Negative amounts becoming huge positive numbers
- Reward calculations producing unexpected results

This is one of the most common vulnerabilities in smart contracts across all blockchains.
    `,
    vulnerableCode: `use anchor_lang::prelude::*;

declare_id!("Vuln333333333333333333333333333333333333333");

#[program]
pub mod vulnerable_overflow {
    use super::*;

    // ❌ VULNERABLE: Unchecked arithmetic operations
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ VULNERABLE: Can overflow!
        // If vault.balance = u64::MAX - 100 and amount = 200
        // Result wraps to 99 instead of failing!
        vault.balance = vault.balance + amount;
        
        msg!("Deposited {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    // ❌ VULNERABLE: Unchecked subtraction
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ VULNERABLE: Can underflow!
        // If vault.balance = 100 and amount = 200
        // Result wraps to u64::MAX - 99 (massive number!)
        vault.balance = vault.balance - amount;
        
        msg!("Withdrew {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    // ❌ VULNERABLE: Unchecked multiplication in rewards
    pub fn calculate_rewards(ctx: Context<CalculateRewards>) -> Result<()> {
        let staking = &mut ctx.accounts.staking;
        let clock = Clock::get()?;
        
        let time_staked = clock.unix_timestamp - staking.start_time;
        
        // ❌ VULNERABLE: Multiplication can overflow!
        // Large stake * high rate * long time = overflow
        let rewards = staking.amount * staking.rate * time_staked as u64;
        
        staking.pending_rewards = rewards;
        msg!("Calculated rewards: {}", rewards);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CalculateRewards<'info> {
    #[account(mut)]
    pub staking: Account<'info, StakingAccount>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[account]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub amount: u64,
    pub rate: u64,
    pub start_time: i64,
    pub pending_rewards: u64,
}`,
    secureCode: `use anchor_lang::prelude::*;

declare_id!("Secure3333333333333333333333333333333333333");

#[program]
pub mod secure_overflow {
    use super::*;

    // ✅ SECURE: Using checked arithmetic
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ✅ SECURE: checked_add returns None on overflow
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        msg!("Deposited {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    // ✅ SECURE: Using checked subtraction with balance validation
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ✅ SECURE: Explicit balance check first
        require!(
            vault.balance >= amount,
            ErrorCode::InsufficientBalance
        );
        
        // ✅ SECURE: checked_sub for defense in depth
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticUnderflow)?;
        
        msg!("Withdrew {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    // ✅ SECURE: Safe reward calculation with overflow protection
    pub fn calculate_rewards(ctx: Context<CalculateRewards>) -> Result<()> {
        let staking = &mut ctx.accounts.staking;
        let clock = Clock::get()?;
        
        // ✅ SECURE: Validate time hasn't gone backwards
        require!(
            clock.unix_timestamp >= staking.start_time,
            ErrorCode::InvalidTimestamp
        );
        
        let time_staked = (clock.unix_timestamp - staking.start_time) as u64;
        
        // ✅ SECURE: Chain checked operations
        // Using u128 intermediate to prevent overflow, then check bounds
        let rewards_u128 = (staking.amount as u128)
            .checked_mul(staking.rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_mul(time_staked as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(1_000_000) // Scale factor
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        // ✅ SECURE: Verify result fits in u64
        require!(
            rewards_u128 <= u64::MAX as u128,
            ErrorCode::RewardsTooLarge
        );
        
        staking.pending_rewards = rewards_u128 as u64;
        msg!("Calculated rewards: {}", staking.pending_rewards);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        has_one = authority @ ErrorCode::UnauthorizedWithdraw
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CalculateRewards<'info> {
    #[account(mut)]
    pub staking: Account<'info, StakingAccount>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[account]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub amount: u64,
    pub rate: u64,
    pub start_time: i64,
    pub pending_rewards: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
    #[msg("Arithmetic underflow occurred")]
    ArithmeticUnderflow,
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
    #[msg("Unauthorized withdrawal attempt")]
    UnauthorizedWithdraw,
    #[msg("Invalid timestamp detected")]
    InvalidTimestamp,
    #[msg("Calculated rewards exceed maximum")]
    RewardsTooLarge,
}`,
    vulnerableExplanation: `
**What's Wrong:**
- Uses standard arithmetic operators (+, -, *)
- In release mode, these wrap on overflow/underflow
- No validation of operation results
- No bounds checking before operations

**Attack Vectors:**

1. **Underflow Attack:**
   - Vault has 100 tokens
   - Attacker withdraws 200 tokens
   - Balance becomes u64::MAX - 99 ≈ 18 quintillion!
   
2. **Overflow Attack:**
   - Stake large amount with high rate
   - Wait for time_staked to be large
   - Multiplication overflows to small number
   - Or wraps to give attacker huge rewards
    `,
    secureExplanation: `
**Security Measures:**

1. **checked_add/checked_sub/checked_mul**: Return None on overflow
2. **Explicit bounds checking**: Validate before operations
3. **u128 intermediate**: Use larger type for calculations
4. **Result validation**: Ensure final value fits in target type

**Best Practices:**
- Always use checked arithmetic in financial code
- Validate inputs before operations
- Use larger intermediate types for complex calculations
- Add explicit bounds checks as defense in depth
    `,
    attackScenario: `
**Real-World Attack Scenario:**

1. A staking protocol calculates rewards: amount * rate * time
2. Attacker stakes maximum u64 amount
3. Waits for time to accumulate
4. Calls calculate_rewards:
   - u64::MAX * rate * time overflows
   - Result wraps to a small or zero value
   - OR wraps to give attacker massive rewards
5. Attacker claims inflated rewards or griefs other users

**Historical Impact:** Integer overflow bugs have caused losses exceeding $100M across DeFi.
    `,
    prevention: [
      'Always use checked_add, checked_sub, checked_mul, checked_div',
      'Use saturating_* methods when capping at max/min is acceptable',
      'Validate inputs before performing arithmetic',
      'Use larger intermediate types (u128) for complex calculations',
      'Add explicit bounds checks even with checked arithmetic',
      'Consider using libraries like uint for arbitrary precision',
    ],
    references: [
      { title: 'Rust Checked Arithmetic', url: 'https://doc.rust-lang.org/std/primitive.u64.html#method.checked_add' },
      { title: 'Solana Security Best Practices', url: 'https://solana.com/docs/programs/security' },
    ],
  },
  {
    id: 'pda-seed-collision',
    title: 'PDA Seed Collision',
    description: 'Using predictable or insufficient seeds for PDAs, allowing attackers to access or overwrite accounts.',
    severity: 'high',
    category: 'PDA Security',
    explanation: `
Program Derived Addresses (PDAs) are deterministically generated from seeds and a program ID. If the seeds are predictable or don't include sufficient unique identifiers, attackers can:

1. **Predict PDAs**: Calculate addresses before they're created
2. **Collide PDAs**: Create accounts that map to the same address
3. **Access Control Bypass**: Access accounts meant for other users

Common mistakes include:
- Using only user-controlled data as seeds
- Not including unique identifiers (user pubkey, nonce)
- Using sequential or predictable values
- Not validating PDA derivation in instructions
    `,
    vulnerableCode: `use anchor_lang::prelude::*;

declare_id!("Vuln444444444444444444444444444444444444444");

#[program]
pub mod vulnerable_pda {
    use super::*;

    // ❌ VULNERABLE: Predictable seeds without user binding
    pub fn create_vault(
        ctx: Context<CreateVault>,
        vault_name: String,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.name = vault_name;
        
        msg!("Created vault: {}", vault.name);
        Ok(())
    }

    // ❌ VULNERABLE: No PDA verification in withdraw
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Only checks authority matches, but PDA could be wrong!
        require_keys_eq!(
            vault.authority,
            ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );
        
        vault.balance = vault.balance.checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(vault_name: String)]
pub struct CreateVault<'info> {
    // ❌ VULNERABLE: Seeds only use vault_name
    // Any user can create a vault with the same name
    // First user's vault gets overwritten!
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", vault_name.as_bytes()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // ❌ VULNERABLE: No seeds constraint to verify PDA
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    #[max_len(32)]
    pub name: String,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}`,
    secureCode: `use anchor_lang::prelude::*;

declare_id!("Secure4444444444444444444444444444444444444");

#[program]
pub mod secure_pda {
    use super::*;

    // ✅ SECURE: User-bound PDA with proper seeds
    pub fn create_vault(
        ctx: Context<CreateVault>,
        vault_name: String,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.name = vault_name;
        vault.bump = ctx.bumps.vault;
        
        msg!("Created vault '{}' for user {}", 
            vault.name, 
            vault.authority
        );
        Ok(())
    }

    // ✅ SECURE: PDA verification in withdraw
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        vault.balance = vault.balance.checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        
        msg!("Withdrew {} from vault '{}'", amount, vault.name);
        Ok(())
    }
    
    // ✅ SECURE: Using PDA for signing (e.g., token transfers)
    pub fn transfer_from_vault(
        ctx: Context<TransferFromVault>,
        amount: u64,
    ) -> Result<()> {
        let vault = &ctx.accounts.vault;
        let authority_key = ctx.accounts.authority.key();
        
        // ✅ SECURE: Reconstruct seeds for PDA signing
        let seeds = &[
            b"vault".as_ref(),
            authority_key.as_ref(),
            vault.name.as_bytes(),
            &[vault.bump],
        ];
        let signer_seeds = &[&seeds[..]];
        
        // Use signer_seeds for CPI calls...
        msg!("Transfer {} from vault PDA", amount);
        
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(vault_name: String)]
pub struct CreateVault<'info> {
    // ✅ SECURE: Seeds include authority pubkey
    // Each user gets their own unique vault PDA
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [
            b"vault",
            authority.key().as_ref(),
            vault_name.as_bytes()
        ],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction()]
pub struct Withdraw<'info> {
    // ✅ SECURE: Full PDA verification with seeds
    #[account(
        mut,
        seeds = [
            b"vault",
            authority.key().as_ref(),
            vault.name.as_bytes()
        ],
        bump = vault.bump,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferFromVault<'info> {
    #[account(
        seeds = [
            b"vault",
            authority.key().as_ref(),
            vault.name.as_bytes()
        ],
        bump = vault.bump,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    #[max_len(32)]
    pub name: String,
    pub bump: u8,  // ✅ Store bump for efficient re-derivation
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access to vault")]
    Unauthorized,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
}`,
    vulnerableExplanation: `
**What's Wrong:**

1. **Insufficient Seeds:**
   - Only uses \`vault_name\` in seeds
   - Two users creating "savings" vault collide
   - Second user overwrites first user's vault

2. **Missing PDA Verification:**
   - Withdraw doesn't verify PDA derivation
   - Attacker can pass any account with matching authority
   - Could access accounts not meant for them

**Attack Vectors:**
- Create vault with common name, wait for victim to deposit
- Pass manipulated account data to withdraw
    `,
    secureExplanation: `
**Security Measures:**

1. **User-Bound Seeds:**
   - Include \`authority.key()\` in seeds
   - Each user gets unique PDA even with same name
   - Impossible to collide with other users

2. **Full PDA Verification:**
   - Seeds constraint in withdraw verifies derivation
   - \`has_one\` ensures authority matches
   - Stored bump enables efficient re-derivation

3. **Bump Storage:**
   - Store bump in account for CPI signing
   - Avoids expensive re-computation
    `,
    attackScenario: `
**Real-World Attack Scenario:**

1. Protocol uses vault_name only for PDA seeds
2. Attacker creates vault named "main" (common name)
3. Victim creates their vault also named "main"
4. Victim's transaction fails OR overwrites attacker's vault
5. If overwrite: attacker's authority is replaced
6. If fail: victim can't create vault, DoS attack

**Alternative Attack:**
1. Attacker predicts common vault names
2. Pre-creates vaults for all common names
3. Sets themselves as authority
4. Waits for victims to deposit to "their" vaults
5. Drains all deposits
    `,
    prevention: [
      'Always include user pubkey in PDA seeds',
      'Use unique identifiers (timestamps, counters) when needed',
      'Verify PDA derivation in all instructions that access PDAs',
      'Store and validate bump seeds',
      'Use has_one constraint for authority checks',
      'Consider using canonical bump (first valid bump)',
    ],
    references: [
      { title: 'Anchor PDA Documentation', url: 'https://www.anchor-lang.com/docs/pdas' },
      { title: 'Solana PDA Deep Dive', url: 'https://solana.com/docs/core/pda' },
    ],
  },
  {
    id: 'unsafe-cpi',
    title: 'Unsafe Cross-Program Invocation (CPI)',
    description: 'Improper CPI handling leading to privilege escalation, reentrancy, or unauthorized program calls.',
    severity: 'critical',
    category: 'CPI Security',
    explanation: `
Cross-Program Invocation (CPI) allows programs to call other programs. This powerful feature introduces several security risks:

1. **Privilege Escalation**: Passing signer seeds incorrectly
2. **Reentrancy**: Called program calls back into your program
3. **Fake Program**: Calling a malicious program instead of intended one
4. **Account Confusion**: Passing wrong accounts to CPI

CPI security requires:
- Verifying the program being called
- Careful handling of signer privileges
- State management before/after CPI
- Understanding the called program's behavior
    `,
    vulnerableCode: `use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Vuln555555555555555555555555555555555555555");

#[program]
pub mod vulnerable_cpi {
    use super::*;

    // ❌ VULNERABLE: No program ID verification for CPI
    pub fn swap_tokens(
        ctx: Context<SwapTokens>,
        amount: u64,
    ) -> Result<()> {
        // ❌ VULNERABLE: Calling unverified program!
        // Attacker can pass a malicious program that steals funds
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_a.to_account_info(),
            to: ctx.accounts.pool_token_a.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        
        // ❌ VULNERABLE: token_program is not verified!
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        
        token::transfer(cpi_ctx, amount)?;
        
        // State update AFTER CPI - vulnerable to reentrancy
        let pool = &mut ctx.accounts.pool;
        pool.total_deposits += amount;
        
        Ok(())
    }

    // ❌ VULNERABLE: Reentrancy through callback
    pub fn deposit_with_callback(
        ctx: Context<DepositWithCallback>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ VULNERABLE: State updated AFTER external call
        // Malicious callback can re-enter and drain funds
        
        // External call first (BAD!)
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_tokens.to_account_info(),
            to: ctx.accounts.vault_tokens.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        token::transfer(cpi_ctx, amount)?;
        
        // ❌ State update after CPI - REENTRANCY RISK!
        vault.balance += amount;
        vault.last_deposit = Clock::get()?.unix_timestamp;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_token_a: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool_token_a: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    // ❌ VULNERABLE: No verification this is the real token program!
    /// CHECK: Should verify this is Token program
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DepositWithCallback<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub user_tokens: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub vault_tokens: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub total_deposits: u64,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub last_deposit: i64,
}`,
    secureCode: `use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Secure5555555555555555555555555555555555555");

#[program]
pub mod secure_cpi {
    use super::*;

    // ✅ SECURE: Verified program ID for CPI
    pub fn swap_tokens(
        ctx: Context<SwapTokens>,
        amount: u64,
    ) -> Result<()> {
        // ✅ SECURE: Update state BEFORE CPI (checks-effects-interactions)
        let pool = &mut ctx.accounts.pool;
        
        // Validate amount
        require!(amount > 0, ErrorCode::InvalidAmount);
        require!(
            ctx.accounts.user_token_a.amount >= amount,
            ErrorCode::InsufficientBalance
        );
        
        // Update state first
        pool.total_deposits = pool.total_deposits
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        // ✅ SECURE: CPI with verified token program
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_a.to_account_info(),
            to: ctx.accounts.pool_token_a.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        
        // Program<'info, Token> ensures this is the real token program
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        
        token::transfer(cpi_ctx, amount)?;
        
        emit!(SwapEvent {
            user: ctx.accounts.user.key(),
            amount,
            timestamp: Clock::get()?.unix_timestamp,
        });
        
        Ok(())
    }

    // ✅ SECURE: Reentrancy-safe deposit
    pub fn deposit_with_callback(
        ctx: Context<DepositWithCallback>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ✅ SECURE: Validate inputs
        require!(amount > 0, ErrorCode::InvalidAmount);
        require!(
            ctx.accounts.user_tokens.amount >= amount,
            ErrorCode::InsufficientBalance
        );
        
        // ✅ SECURE: Update state BEFORE external call
        // This prevents reentrancy attacks
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        vault.last_deposit = Clock::get()?.unix_timestamp;
        
        // ✅ SECURE: Set reentrancy guard (optional extra protection)
        require!(!vault.locked, ErrorCode::ReentrancyDetected);
        vault.locked = true;
        
        // External call AFTER state update
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_tokens.to_account_info(),
            to: ctx.accounts.vault_tokens.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        token::transfer(cpi_ctx, amount)?;
        
        // ✅ Release reentrancy guard
        let vault = &mut ctx.accounts.vault;
        vault.locked = false;
        
        Ok(())
    }
    
    // ✅ SECURE: CPI with PDA signer
    pub fn transfer_from_pool(
        ctx: Context<TransferFromPool>,
        amount: u64,
    ) -> Result<()> {
        let pool = &ctx.accounts.pool;
        
        // ✅ SECURE: Construct signer seeds carefully
        let pool_seed = pool.seed.as_bytes();
        let bump = pool.bump;
        let seeds = &[
            b"pool".as_ref(),
            pool_seed,
            &[bump],
        ];
        let signer_seeds = &[&seeds[..]];
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.pool_tokens.to_account_info(),
            to: ctx.accounts.recipient_tokens.to_account_info(),
            authority: ctx.accounts.pool.to_account_info(),
        };
        
        // ✅ SECURE: CPI with signer seeds
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        mut,
        constraint = user_token_a.owner == user.key() @ ErrorCode::InvalidOwner
    )]
    pub user_token_a: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = pool_token_a.owner == pool.key() @ ErrorCode::InvalidOwner
    )]
    pub pool_token_a: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    // ✅ SECURE: Program<'info, Token> verifies program ID
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DepositWithCallback<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        mut,
        constraint = user_tokens.owner == user.key() @ ErrorCode::InvalidOwner
    )]
    pub user_tokens: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub vault_tokens: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct TransferFromPool<'info> {
    #[account(
        seeds = [b"pool", pool.seed.as_bytes()],
        bump = pool.bump,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub pool_tokens: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub recipient_tokens: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub seed: String,
    pub bump: u8,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub last_deposit: i64,
    pub locked: bool,  // Reentrancy guard
}

#[event]
pub struct SwapEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Insufficient balance")]
    InsufficientBalance,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Invalid token account owner")]
    InvalidOwner,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Reentrancy detected")]
    ReentrancyDetected,
}`,
    vulnerableExplanation: `
**What's Wrong:**

1. **Unverified Program:**
   - \`token_program\` is raw AccountInfo
   - Attacker can pass malicious program
   - Fake program can steal tokens

2. **Reentrancy Risk:**
   - State updated AFTER CPI
   - Malicious token can callback
   - Re-enter and exploit stale state

3. **Missing Validations:**
   - No ownership checks on token accounts
   - No amount validation
   - No overflow protection
    `,
    secureExplanation: `
**Security Measures:**

1. **Program Verification:**
   - \`Program<'info, Token>\` verifies program ID
   - Cannot pass fake token program

2. **Checks-Effects-Interactions:**
   - Update state BEFORE CPI
   - Reentrancy can't exploit stale state

3. **Reentrancy Guard:**
   - Lock flag prevents re-entry
   - Extra protection layer

4. **Comprehensive Validation:**
   - Token account ownership
   - Amount bounds
   - Overflow protection
    `,
    attackScenario: `
**Reentrancy Attack Scenario:**

1. Attacker deploys malicious token contract
2. Token's transfer function calls back to deposit
3. Attack flow:
   - Call deposit(100)
   - CPI to malicious token
   - Token calls deposit(100) again
   - State not yet updated, passes checks
   - Repeat until drained
4. Final state shows deposits but tokens stolen

**Fake Program Attack:**

1. Attacker deploys fake "token program"
2. Fake program's transfer does nothing
3. Attacker calls swap with fake program
4. Pool state updated (thinks it received tokens)
5. Attacker gets output tokens for free
    `,
    prevention: [
      'Always use Program<\'info, T> for CPI targets',
      'Follow checks-effects-interactions pattern',
      'Update state BEFORE external calls',
      'Consider reentrancy guards for complex flows',
      'Validate all account relationships',
      'Use events for off-chain tracking',
      'Test with malicious program simulations',
    ],
    references: [
      { title: 'Anchor CPI Documentation', url: 'https://www.anchor-lang.com/docs/cross-program-invocations' },
      { title: 'Solana CPI Deep Dive', url: 'https://solana.com/docs/core/cpi' },
    ],
  },
  {
    id: 'account-data-matching',
    title: 'Account Data Matching Vulnerabilities',
    description: 'Failing to verify relationships between accounts, allowing attackers to substitute malicious accounts.',
    severity: 'high',
    category: 'Account Validation',
    explanation: `
Solana programs often work with multiple related accounts (e.g., a user account and their token account, or a pool and its vaults). Failing to verify these relationships allows attackers to:

1. **Substitute Accounts**: Pass their own account instead of the expected one
2. **Steal Funds**: Redirect transfers to attacker-controlled accounts
3. **Bypass Access Control**: Use accounts from different contexts

Common patterns that need validation:
- Token account ownership
- PDA derivation relationships
- Authority/owner fields matching signers
- Mint relationships for token accounts
    `,
    vulnerableCode: `use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer};

declare_id!("Vuln666666666666666666666666666666666666666");

#[program]
pub mod vulnerable_matching {
    use super::*;

    // ❌ VULNERABLE: No verification that token accounts belong to user
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64,
    ) -> Result<()> {
        // ❌ VULNERABLE: from_account might not belong to user!
        // Attacker can pass victim's token account as from_account
        let cpi_accounts = Transfer {
            from: ctx.accounts.from_account.to_account_info(),
            to: ctx.accounts.to_account.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    // ❌ VULNERABLE: No mint verification
    pub fn deposit_to_pool(
        ctx: Context<DepositToPool>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // ❌ VULNERABLE: user_tokens might be for wrong mint!
        // Attacker deposits worthless tokens, gets valuable pool shares
        pool.total_deposits += amount;
        
        // Transfer happens but mint isn't verified
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_tokens.to_account_info(),
            to: ctx.accounts.pool_tokens.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    // ❌ VULNERABLE: No relationship verification between accounts
    pub fn claim_rewards(
        ctx: Context<ClaimRewards>,
    ) -> Result<()> {
        let staking = &ctx.accounts.staking_account;
        let rewards = staking.pending_rewards;
        
        // ❌ VULNERABLE: reward_vault might not be the pool's vault!
        // Attacker can pass any vault they control
        
        msg!("Claiming {} rewards", rewards);
        
        // Would transfer from wrong vault...
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    // ❌ VULNERABLE: No owner constraint
    #[account(mut)]
    pub from_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub to_account: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DepositToPool<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ❌ VULNERABLE: No mint constraint
    #[account(mut)]
    pub user_tokens: Account<'info, TokenAccount>,
    
    // ❌ VULNERABLE: No relationship to pool verified
    #[account(mut)]
    pub pool_tokens: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub staking_account: Account<'info, StakingAccount>,
    
    // ❌ VULNERABLE: No verification this is the correct reward vault
    #[account(mut)]
    pub reward_vault: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_reward_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub token_mint: Pubkey,
}

#[account]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub pool: Pubkey,
    pub amount: u64,
    pub pending_rewards: u64,
}`,
    secureCode: `use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer};

declare_id!("Secure6666666666666666666666666666666666666");

#[program]
pub mod secure_matching {
    use super::*;

    // ✅ SECURE: Full account relationship verification
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64,
    ) -> Result<()> {
        // All validations handled by constraints
        // from_account.owner == authority is verified
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.from_account.to_account_info(),
            to: ctx.accounts.to_account.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        
        token::transfer(cpi_ctx, amount)?;
        
        emit!(TransferEvent {
            from: ctx.accounts.from_account.key(),
            to: ctx.accounts.to_account.key(),
            amount,
            authority: ctx.accounts.authority.key(),
        });
        
        Ok(())
    }

    // ✅ SECURE: Mint and relationship verification
    pub fn deposit_to_pool(
        ctx: Context<DepositToPool>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // Validate amount
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        // Update state with overflow protection
        pool.total_deposits = pool.total_deposits
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        // All account relationships verified by constraints
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_tokens.to_account_info(),
            to: ctx.accounts.pool_tokens.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    // ✅ SECURE: Full relationship chain verification
    pub fn claim_rewards(
        ctx: Context<ClaimRewards>,
    ) -> Result<()> {
        let staking = &mut ctx.accounts.staking_account;
        let pool = &ctx.accounts.pool;
        
        let rewards = staking.pending_rewards;
        require!(rewards > 0, ErrorCode::NoRewardsToClaim);
        
        // Clear pending rewards BEFORE transfer (CEI pattern)
        staking.pending_rewards = 0;
        
        // Construct PDA signer for pool
        let pool_seeds = &[
            b"pool".as_ref(),
            pool.token_mint.as_ref(),
            &[pool.bump],
        ];
        let signer_seeds = &[&pool_seeds[..]];
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.reward_vault.to_account_info(),
            to: ctx.accounts.user_reward_account.to_account_info(),
            authority: ctx.accounts.pool.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        
        token::transfer(cpi_ctx, rewards)?;
        
        emit!(RewardClaimEvent {
            user: ctx.accounts.user.key(),
            pool: pool.key(),
            amount: rewards,
        });
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    // ✅ SECURE: Verify from_account is owned by authority
    #[account(
        mut,
        constraint = from_account.owner == authority.key() @ ErrorCode::InvalidOwner,
        constraint = from_account.mint == to_account.mint @ ErrorCode::MintMismatch
    )]
    pub from_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub to_account: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DepositToPool<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ SECURE: Verify mint matches pool's expected mint
    #[account(
        mut,
        constraint = user_tokens.owner == user.key() @ ErrorCode::InvalidOwner,
        constraint = user_tokens.mint == pool.token_mint @ ErrorCode::MintMismatch
    )]
    pub user_tokens: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Verify pool_tokens belongs to pool and has correct mint
    #[account(
        mut,
        constraint = pool_tokens.owner == pool.key() @ ErrorCode::InvalidOwner,
        constraint = pool_tokens.mint == pool.token_mint @ ErrorCode::MintMismatch
    )]
    pub pool_tokens: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Pool PDA verification
    #[account(
        mut,
        seeds = [b"pool", pool.token_mint.as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, Pool>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    pub user: Signer<'info>,
    
    // ✅ SECURE: Verify staking account belongs to user and pool
    #[account(
        mut,
        has_one = owner @ ErrorCode::InvalidOwner,
        constraint = staking_account.pool == pool.key() @ ErrorCode::PoolMismatch
    )]
    pub staking_account: Account<'info, StakingAccount>,
    
    // ✅ SECURE: Verify pool relationship
    #[account(
        seeds = [b"pool", pool.token_mint.as_ref()],
        bump = pool.bump,
        has_one = reward_vault @ ErrorCode::InvalidRewardVault
    )]
    pub pool: Account<'info, Pool>,
    
    // ✅ SECURE: Verified through has_one on pool
    #[account(mut)]
    pub reward_vault: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Verify user owns the reward account
    #[account(
        mut,
        constraint = user_reward_account.owner == user.key() @ ErrorCode::InvalidOwner,
        constraint = user_reward_account.mint == pool.reward_mint @ ErrorCode::MintMismatch
    )]
    pub user_reward_account: Account<'info, TokenAccount>,
    
    /// CHECK: Verified as staking_account.owner
    #[account(constraint = owner.key() == user.key() @ ErrorCode::InvalidOwner)]
    pub owner: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub token_mint: Pubkey,
    pub reward_mint: Pubkey,
    pub reward_vault: Pubkey,
    pub bump: u8,
}

#[account]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub pool: Pubkey,
    pub amount: u64,
    pub pending_rewards: u64,
}

#[event]
pub struct TransferEvent {
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
    pub authority: Pubkey,
}

#[event]
pub struct RewardClaimEvent {
    pub user: Pubkey,
    pub pool: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid account owner")]
    InvalidOwner,
    #[msg("Token mint mismatch")]
    MintMismatch,
    #[msg("Pool mismatch")]
    PoolMismatch,
    #[msg("Invalid reward vault")]
    InvalidRewardVault,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("No rewards to claim")]
    NoRewardsToClaim,
}`,
    vulnerableExplanation: `
**What's Wrong:**

1. **No Owner Verification:**
   - Token accounts not verified to belong to signer
   - Attacker can pass victim's accounts

2. **No Mint Verification:**
   - Token mints not checked
   - Attacker deposits worthless tokens

3. **No Relationship Verification:**
   - Pool and vault relationship not verified
   - Attacker can redirect rewards

**Attack Vectors:**
- Pass victim's token account as source
- Deposit fake tokens, get real pool shares
- Claim rewards from wrong vault
    `,
    secureExplanation: `
**Security Measures:**

1. **Owner Constraints:**
   - \`token_account.owner == signer.key()\`
   - Ensures accounts belong to transaction signer

2. **Mint Constraints:**
   - \`user_tokens.mint == pool.token_mint\`
   - Prevents depositing wrong tokens

3. **Relationship Chains:**
   - \`has_one\` verifies stored references
   - PDA seeds verify derivation
   - Full chain from user → staking → pool → vault

4. **Defense in Depth:**
   - Multiple validation layers
   - Events for audit trail
    `,
    attackScenario: `
**Account Substitution Attack:**

1. Pool accepts USDC deposits
2. Attacker creates worthless "FAKE" token
3. Attacker:
   - Creates FAKE token account
   - Calls deposit with FAKE tokens
   - No mint verification, deposit succeeds
   - Receives pool shares worth real USDC
4. Attacker redeems shares for real USDC
5. Pool is drained of real value

**Reward Theft Attack:**

1. Attacker finds pool with large reward vault
2. Creates fake staking account pointing to pool
3. Sets pending_rewards to maximum
4. Calls claim_rewards with:
   - Fake staking account
   - Real pool's reward vault
5. Drains entire reward vault
    `,
    prevention: [
      'Always verify token account ownership matches signer',
      'Verify mint relationships for all token operations',
      'Use has_one for stored account references',
      'Verify full relationship chains (user → account → pool)',
      'Use PDAs to enforce account derivation',
      'Add events for monitoring and auditing',
      'Test with account substitution scenarios',
    ],
    references: [
      { title: 'Anchor Constraints', url: 'https://www.anchor-lang.com/docs/account-constraints' },
      { title: 'SPL Token Security', url: 'https://spl.solana.com/token' },
    ],
  },
];

export const getPatternById = (id: string): SecurityPattern | undefined => {
  return securityPatterns.find(pattern => pattern.id === id);
};
