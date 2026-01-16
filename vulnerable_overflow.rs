//! # Vulnerable Integer Overflow Example
//! 
//! This program demonstrates CRITICAL vulnerabilities from unchecked arithmetic.
//! 
//! ## Vulnerability
//! In Rust release mode (which Solana uses), arithmetic operations wrap on overflow
//! instead of panicking. This means:
//! - u64::MAX + 1 = 0
//! - 0 - 1 = u64::MAX (18,446,744,073,709,551,615)
//! 
//! ## Attack Vectors
//! 1. **Underflow**: Withdraw more than balance, balance wraps to huge number
//! 2. **Overflow**: Deposit to near-max balance, wrap to small number
//! 3. **Multiplication overflow**: Large stake * rate * time = small number
//! 
//! ## Impact
//! - Infinite money glitch
//! - Balance manipulation
//! - Reward calculation exploits
//! 
//! ## DO NOT USE IN PRODUCTION

use anchor_lang::prelude::*;

declare_id!("Vuln333333333333333333333333333333333333333");

#[program]
pub mod vulnerable_overflow {
    use super::*;

    /// Initialize a vault
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        Ok(())
    }

    /// ❌ VULNERABLE: Deposit with unchecked addition
    /// 
    /// Attack scenario:
    /// 1. Vault balance is u64::MAX - 100
    /// 2. Attacker deposits 200
    /// 3. Balance wraps: (u64::MAX - 100) + 200 = 99
    /// 4. Attacker effectively destroyed most of the vault's balance
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ VULNERABLE: Standard addition wraps on overflow!
        // In release mode, this silently wraps instead of panicking
        vault.balance = vault.balance + amount;
        
        msg!("Deposited {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ❌ VULNERABLE: Withdraw with unchecked subtraction
    /// 
    /// Attack scenario:
    /// 1. Vault balance is 100
    /// 2. Attacker withdraws 200
    /// 3. Balance wraps: 100 - 200 = u64::MAX - 99
    /// 4. Attacker now has "infinite" balance to withdraw
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ VULNERABLE: Standard subtraction wraps on underflow!
        // 100 - 200 = 18,446,744,073,709,551,515 (u64::MAX - 99)
        vault.balance = vault.balance - amount;
        
        msg!("Withdrew {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ❌ VULNERABLE: Reward calculation with unchecked multiplication
    /// 
    /// Attack scenario:
    /// 1. Stake amount: 1,000,000,000,000 (1 trillion)
    /// 2. Rate: 1,000,000 (100% APY scaled)
    /// 3. Time: 31,536,000 (1 year in seconds)
    /// 4. Multiplication overflows, result wraps to small number
    /// 5. User gets way less rewards than expected, or
    /// 6. Attacker manipulates to get more rewards
    pub fn calculate_rewards(ctx: Context<CalculateRewards>) -> Result<()> {
        let staking = &mut ctx.accounts.staking;
        let clock = Clock::get()?;
        
        let time_staked = clock.unix_timestamp - staking.start_time;
        
        // ❌ VULNERABLE: Multiplication can overflow!
        // Large numbers multiply to overflow and wrap
        let rewards = staking.amount * staking.rate * time_staked as u64;
        
        staking.pending_rewards = rewards;
        msg!("Calculated rewards: {}", rewards);
        Ok(())
    }

    /// ❌ VULNERABLE: Division truncation issues
    /// 
    /// Attack scenario:
    /// 1. User swaps 999 tokens at rate 1000:1
    /// 2. 999 / 1000 = 0 (integer division truncates)
    /// 3. User loses their tokens, gets nothing back
    pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // ❌ VULNERABLE: Integer division truncates!
        // Small amounts get rounded to zero
        let amount_out = amount_in / pool.rate;
        
        // User pays amount_in but might get 0 back
        pool.reserve_in = pool.reserve_in + amount_in;
        pool.reserve_out = pool.reserve_out - amount_out;
        
        msg!("Swapped {} for {}", amount_in, amount_out);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
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

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    pub user: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[account]
#[derive(InitSpace)]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub amount: u64,
    pub rate: u64,
    pub start_time: i64,
    pub pending_rewards: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub reserve_in: u64,
    pub reserve_out: u64,
    pub rate: u64,
}

// ============================================================================
// ATTACK DEMONSTRATIONS
// ============================================================================
//
// UNDERFLOW ATTACK:
// -----------------
// Initial state: vault.balance = 100
// 
// Attacker calls: withdraw(200)
// Calculation: 100 - 200 = -100 (wraps to u64::MAX - 99)
// Final state: vault.balance = 18,446,744,073,709,551,515
//
// Attacker can now withdraw this massive "balance"
//
// OVERFLOW ATTACK:
// ----------------
// Initial state: vault.balance = u64::MAX - 50
// 
// Attacker calls: deposit(100)
// Calculation: (u64::MAX - 50) + 100 = 49 (wraps around)
// Final state: vault.balance = 49
//
// Attacker destroyed most of the vault's balance
//
// MULTIPLICATION OVERFLOW:
// ------------------------
// staking.amount = 10^18 (1 quintillion)
// staking.rate = 10^6
// time_staked = 10^7
//
// Calculation: 10^18 * 10^6 * 10^7 = 10^31
// But u64::MAX ≈ 1.8 * 10^19
// Result wraps multiple times, giving unpredictable small number
