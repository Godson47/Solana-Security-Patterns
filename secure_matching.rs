//! # Secure Account Matching Example
//! 
//! This program demonstrates CORRECT account relationship verification.
//! 
//! ## Security Measures
//! 1. Verify token account ownership matches signer
//! 2. Verify mint relationships for all token operations
//! 3. Use has_one for stored account references
//! 4. Verify full relationship chains
//! 
//! ## Best Practices
//! - Always verify token account ownership
//! - Verify mint relationships for all token operations
//! - Use has_one for stored account references
//! - Verify full relationship chains (user → account → pool)

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer, Mint};

declare_id!("Secure6666666666666666666666666666666666666");

#[program]
pub mod secure_matching {
    use super::*;

    /// ✅ SECURE: Transfer with full ownership verification
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        // All validations handled by constraints:
        // - from_account.owner == authority
        // - from_account.mint == to_account.mint
        
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
        
        emit!(TransferExecuted {
            from: ctx.accounts.from_account.key(),
            to: ctx.accounts.to_account.key(),
            amount,
            authority: ctx.accounts.authority.key(),
        });
        
        msg!("Transferred {} tokens", amount);
        Ok(())
    }

    /// ✅ SECURE: Deposit with mint and relationship verification
    pub fn deposit_to_pool(
        ctx: Context<DepositToPool>,
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let pool = &mut ctx.accounts.pool;
        
        // All validations handled by constraints:
        // - user_tokens.mint == pool.token_mint
        // - pool_tokens.mint == pool.token_mint
        // - pool_tokens.owner == pool.key()
        
        // Update pool state
        pool.total_deposits = pool.total_deposits
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        // Calculate shares (simplified - real implementation would be more complex)
        let shares = if pool.total_shares == 0 {
            amount
        } else {
            (amount as u128)
                .checked_mul(pool.total_shares as u128)
                .ok_or(ErrorCode::Overflow)?
                .checked_div(pool.total_deposits.saturating_sub(amount) as u128)
                .ok_or(ErrorCode::Overflow)? as u64
        };
        
        pool.total_shares = pool.total_shares
            .checked_add(shares)
            .ok_or(ErrorCode::Overflow)?;
        
        // Transfer tokens
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
        
        emit!(DepositMade {
            pool: pool.key(),
            user: ctx.accounts.user.key(),
            amount,
            shares,
        });
        
        msg!("Deposited {} tokens, received {} shares", amount, shares);
        Ok(())
    }

    /// ✅ SECURE: Claim rewards with full relationship verification
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let staking = &mut ctx.accounts.staking_account;
        let pool = &ctx.accounts.pool;
        
        let rewards = staking.pending_rewards;
        require!(rewards > 0, ErrorCode::NoRewardsToClaim);
        
        // All validations handled by constraints:
        // - staking_account.owner == user
        // - staking_account.pool == pool.key()
        // - pool.reward_vault == reward_vault.key()
        // - user_reward_account.owner == user
        // - user_reward_account.mint == pool.reward_mint
        
        // Clear pending rewards BEFORE transfer (CEI pattern)
        staking.pending_rewards = 0;
        staking.total_claimed = staking.total_claimed
            .checked_add(rewards)
            .ok_or(ErrorCode::Overflow)?;
        
        // Transfer rewards using pool PDA as signer
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
        
        emit!(RewardsClaimed {
            staking_account: staking.key(),
            user: ctx.accounts.user.key(),
            pool: pool.key(),
            amount: rewards,
        });
        
        msg!("Claimed {} rewards", rewards);
        Ok(())
    }

    /// ✅ SECURE: Stake with pool relationship verification
    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let staking = &mut ctx.accounts.staking_account;
        let pool = &mut ctx.accounts.pool;
        
        // All validations handled by constraints:
        // - staking_account.owner == user
        // - staking_account.pool == pool.key()
        // - user_tokens.owner == user
        // - user_tokens.mint == pool.token_mint
        
        // Update staking account
        staking.amount = staking.amount
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        staking.last_stake_time = Clock::get()?.unix_timestamp;
        
        // Update pool
        pool.total_staked = pool.total_staked
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        // Transfer tokens to pool
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
        
        emit!(Staked {
            staking_account: staking.key(),
            user: ctx.accounts.user.key(),
            pool: pool.key(),
            amount,
        });
        
        msg!("Staked {} tokens", amount);
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
    
    // ✅ SECURE: Verify pool and its reward vault
    #[account(
        seeds = [b"pool", pool.token_mint.as_ref()],
        bump = pool.bump,
        has_one = reward_vault @ ErrorCode::InvalidRewardVault
    )]
    pub pool: Account<'info, Pool>,
    
    // ✅ SECURE: Verified through has_one on pool
    #[account(mut)]
    pub reward_vault: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Verify user owns the reward account and mint matches
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

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ SECURE: Verify staking account ownership and pool relationship
    #[account(
        mut,
        has_one = owner @ ErrorCode::InvalidOwner,
        constraint = staking_account.pool == pool.key() @ ErrorCode::PoolMismatch
    )]
    pub staking_account: Account<'info, StakingAccount>,
    
    // ✅ SECURE: Verify user token account
    #[account(
        mut,
        constraint = user_tokens.owner == user.key() @ ErrorCode::InvalidOwner,
        constraint = user_tokens.mint == pool.token_mint @ ErrorCode::MintMismatch
    )]
    pub user_tokens: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Verify pool token account
    #[account(
        mut,
        constraint = pool_tokens.owner == pool.key() @ ErrorCode::InvalidOwner,
        constraint = pool_tokens.mint == pool.token_mint @ ErrorCode::MintMismatch
    )]
    pub pool_tokens: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        seeds = [b"pool", pool.token_mint.as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, Pool>,
    
    /// CHECK: Verified as staking_account.owner
    #[account(constraint = owner.key() == user.key() @ ErrorCode::InvalidOwner)]
    pub owner: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub token_mint: Pubkey,
    pub reward_mint: Pubkey,
    pub reward_vault: Pubkey,
    pub total_deposits: u64,
    pub total_shares: u64,
    pub total_staked: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub pool: Pubkey,
    pub amount: u64,
    pub pending_rewards: u64,
    pub total_claimed: u64,
    pub last_stake_time: i64,
}

#[event]
pub struct TransferExecuted {
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
    pub authority: Pubkey,
}

#[event]
pub struct DepositMade {
    pub pool: Pubkey,
    pub user: Pubkey,
    pub amount: u64,
    pub shares: u64,
}

#[event]
pub struct RewardsClaimed {
    pub staking_account: Pubkey,
    pub user: Pubkey,
    pub pool: Pubkey,
    pub amount: u64,
}

#[event]
pub struct Staked {
    pub staking_account: Pubkey,
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
}

// ============================================================================
// SECURITY ANALYSIS
// ============================================================================
//
// Why the attacks from vulnerable_matching.rs FAIL here:
//
// TOKEN THEFT BLOCKED:
// --------------------
// Attacker tries to pass victim's token account:
// 1. Constraint: from_account.owner == authority.key()
// 2. Attacker signs as authority
// 3. Victim's account has victim as owner
// 4. authority.key() != victim's pubkey
// 5. Transaction fails with "Invalid account owner"
//
// FAKE TOKEN DEPOSIT BLOCKED:
// ---------------------------
// Attacker tries to deposit FAKE tokens:
// 1. Constraint: user_tokens.mint == pool.token_mint
// 2. Pool expects USDC mint
// 3. Attacker's FAKE token has different mint
// 4. Transaction fails with "Token mint mismatch"
//
// REWARD THEFT BLOCKED:
// ---------------------
// Attacker tries to claim with fake staking account:
// 1. has_one = owner: staking_account.owner must match
// 2. Constraint: staking_account.pool == pool.key()
// 3. has_one = reward_vault: pool.reward_vault must match
// 4. Fake staking account won't have correct pool reference
// 5. Transaction fails with "Pool mismatch"
//
// Even if attacker creates staking account pointing to real pool:
// - They can't set pending_rewards (only program can)
// - has_one = owner ensures they can only claim their own rewards
