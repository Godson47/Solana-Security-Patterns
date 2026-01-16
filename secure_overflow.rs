//! # Secure Integer Arithmetic Example
//! 
//! This program demonstrates SAFE arithmetic operations in Solana programs.
//! 
//! ## Security Measures
//! 1. Use `checked_add`, `checked_sub`, `checked_mul`, `checked_div`
//! 2. Validate inputs before operations
//! 3. Use larger intermediate types (u128) for complex calculations
//! 4. Add explicit bounds checks as defense-in-depth
//! 
//! ## Best Practices
//! - Always use checked arithmetic in financial code
//! - Validate inputs before operations
//! - Use larger intermediate types for complex calculations
//! - Consider using saturating_* when capping at max/min is acceptable

use anchor_lang::prelude::*;

declare_id!("Secure3333333333333333333333333333333333333");

/// Scale factor for fixed-point arithmetic (6 decimals)
const SCALE: u64 = 1_000_000;

/// Maximum allowed balance to prevent overflow in calculations
const MAX_BALANCE: u64 = u64::MAX / SCALE;

#[program]
pub mod secure_overflow {
    use super::*;

    /// Initialize a vault with safe defaults
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.total_deposited = 0;
        vault.total_withdrawn = 0;
        
        emit!(VaultInitialized {
            vault: vault.key(),
            authority: vault.authority,
        });
        
        Ok(())
    }

    /// ✅ SECURE: Deposit with checked addition and bounds validation
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // ✅ Validate input
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Check bounds BEFORE operation
        require!(
            vault.balance <= MAX_BALANCE.checked_sub(amount).unwrap_or(0),
            ErrorCode::BalanceExceedsMaximum
        );
        
        // ✅ SECURE: checked_add returns None on overflow
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        vault.total_deposited = vault.total_deposited
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        emit!(DepositMade {
            vault: vault.key(),
            depositor: ctx.accounts.depositor.key(),
            amount,
            new_balance: vault.balance,
        });
        
        msg!("Deposited {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ✅ SECURE: Withdraw with explicit balance check and checked subtraction
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // ✅ Validate input
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Explicit balance check FIRST
        require!(
            vault.balance >= amount,
            ErrorCode::InsufficientBalance
        );
        
        // ✅ SECURE: checked_sub for defense in depth
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticUnderflow)?;
        
        vault.total_withdrawn = vault.total_withdrawn
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        emit!(WithdrawalMade {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
            amount,
            remaining_balance: vault.balance,
        });
        
        msg!("Withdrew {}. Remaining balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ✅ SECURE: Reward calculation with u128 intermediate and bounds checking
    pub fn calculate_rewards(ctx: Context<CalculateRewards>) -> Result<()> {
        let staking = &mut ctx.accounts.staking;
        let clock = Clock::get()?;
        
        // ✅ Validate time hasn't gone backwards (clock manipulation protection)
        require!(
            clock.unix_timestamp >= staking.start_time,
            ErrorCode::InvalidTimestamp
        );
        
        let time_staked = (clock.unix_timestamp - staking.start_time) as u64;
        
        // ✅ SECURE: Use u128 for intermediate calculations
        // This prevents overflow during multiplication
        let rewards_u128 = (staking.amount as u128)
            .checked_mul(staking.rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_mul(time_staked as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(SCALE as u128)  // Scale down
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(365 * 24 * 60 * 60)  // Annualize
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        // ✅ SECURE: Verify result fits in u64
        require!(
            rewards_u128 <= u64::MAX as u128,
            ErrorCode::RewardsTooLarge
        );
        
        let rewards = rewards_u128 as u64;
        
        // ✅ Cap rewards at available pool balance
        let capped_rewards = rewards.min(staking.pool_balance);
        
        staking.pending_rewards = staking.pending_rewards
            .checked_add(capped_rewards)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        emit!(RewardsCalculated {
            staking_account: staking.key(),
            owner: staking.owner,
            rewards: capped_rewards,
            time_staked,
        });
        
        msg!("Calculated rewards: {} (capped from {})", capped_rewards, rewards);
        Ok(())
    }

    /// ✅ SECURE: Swap with proper decimal handling and slippage protection
    pub fn swap(
        ctx: Context<Swap>,
        amount_in: u64,
        min_amount_out: u64,  // Slippage protection
    ) -> Result<()> {
        // ✅ Validate inputs
        require!(amount_in > 0, ErrorCode::InvalidAmount);
        require!(min_amount_out > 0, ErrorCode::InvalidMinOutput);
        
        let pool = &mut ctx.accounts.pool;
        
        // ✅ SECURE: Use u128 for price calculation to prevent overflow
        // Formula: amount_out = (amount_in * reserve_out) / (reserve_in + amount_in)
        // This is the constant product formula (x * y = k)
        
        let numerator = (amount_in as u128)
            .checked_mul(pool.reserve_out as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        let denominator = (pool.reserve_in as u128)
            .checked_add(amount_in as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        let amount_out_u128 = numerator
            .checked_div(denominator)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        // ✅ Verify fits in u64
        require!(
            amount_out_u128 <= u64::MAX as u128,
            ErrorCode::OutputTooLarge
        );
        
        let amount_out = amount_out_u128 as u64;
        
        // ✅ Slippage protection
        require!(
            amount_out >= min_amount_out,
            ErrorCode::SlippageExceeded
        );
        
        // ✅ Verify pool has sufficient output reserves
        require!(
            pool.reserve_out >= amount_out,
            ErrorCode::InsufficientLiquidity
        );
        
        // ✅ Update reserves with checked arithmetic
        pool.reserve_in = pool.reserve_in
            .checked_add(amount_in)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        pool.reserve_out = pool.reserve_out
            .checked_sub(amount_out)
            .ok_or(ErrorCode::ArithmeticUnderflow)?;
        
        emit!(SwapExecuted {
            pool: pool.key(),
            user: ctx.accounts.user.key(),
            amount_in,
            amount_out,
        });
        
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
    #[account(
        mut,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CalculateRewards<'info> {
    #[account(
        mut,
        has_one = owner @ ErrorCode::Unauthorized
    )]
    pub staking: Account<'info, StakingAccount>,
    pub owner: Signer<'info>,
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
    pub total_deposited: u64,
    pub total_withdrawn: u64,
}

#[account]
#[derive(InitSpace)]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub amount: u64,
    pub rate: u64,
    pub start_time: i64,
    pub pending_rewards: u64,
    pub pool_balance: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub reserve_in: u64,
    pub reserve_out: u64,
}

#[event]
pub struct VaultInitialized {
    pub vault: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct DepositMade {
    pub vault: Pubkey,
    pub depositor: Pubkey,
    pub amount: u64,
    pub new_balance: u64,
}

#[event]
pub struct WithdrawalMade {
    pub vault: Pubkey,
    pub authority: Pubkey,
    pub amount: u64,
    pub remaining_balance: u64,
}

#[event]
pub struct RewardsCalculated {
    pub staking_account: Pubkey,
    pub owner: Pubkey,
    pub rewards: u64,
    pub time_staked: u64,
}

#[event]
pub struct SwapExecuted {
    pub pool: Pubkey,
    pub user: Pubkey,
    pub amount_in: u64,
    pub amount_out: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
    #[msg("Arithmetic underflow occurred")]
    ArithmeticUnderflow,
    #[msg("Insufficient balance for operation")]
    InsufficientBalance,
    #[msg("Invalid amount - must be greater than zero")]
    InvalidAmount,
    #[msg("Invalid minimum output amount")]
    InvalidMinOutput,
    #[msg("Balance would exceed maximum allowed")]
    BalanceExceedsMaximum,
    #[msg("Invalid timestamp detected")]
    InvalidTimestamp,
    #[msg("Calculated rewards exceed maximum")]
    RewardsTooLarge,
    #[msg("Output amount exceeds maximum")]
    OutputTooLarge,
    #[msg("Slippage tolerance exceeded")]
    SlippageExceeded,
    #[msg("Insufficient liquidity in pool")]
    InsufficientLiquidity,
    #[msg("Unauthorized")]
    Unauthorized,
}

// ============================================================================
// SECURITY ANALYSIS
// ============================================================================
//
// Why the attacks from vulnerable_overflow.rs FAIL here:
//
// UNDERFLOW ATTACK BLOCKED:
// -------------------------
// Attacker tries: withdraw(200) when balance = 100
// 1. Explicit check: require!(vault.balance >= amount) → FAILS
// 2. Even if bypassed: checked_sub(200) → returns None → Error
// Transaction fails with InsufficientBalance or ArithmeticUnderflow
//
// OVERFLOW ATTACK BLOCKED:
// ------------------------
// Attacker tries: deposit(100) when balance = u64::MAX - 50
// 1. Bounds check: balance <= MAX_BALANCE - amount → FAILS
// 2. Even if bypassed: checked_add(100) → returns None → Error
// Transaction fails with BalanceExceedsMaximum or ArithmeticOverflow
//
// MULTIPLICATION OVERFLOW BLOCKED:
// --------------------------------
// Large stake * rate * time calculation:
// 1. All operations use u128 intermediate type
// 2. Each step uses checked_mul/checked_div
// 3. Final result verified to fit in u64
// 4. Rewards capped at pool balance
// Transaction either succeeds with correct value or fails safely
