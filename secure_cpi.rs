//! # Secure CPI Security Example
//! 
//! This program demonstrates SAFE Cross-Program Invocation patterns.
//! 
//! ## Security Measures
//! 1. Use `Program<'info, T>` to verify program IDs
//! 2. Follow Checks-Effects-Interactions (CEI) pattern
//! 3. Implement reentrancy guards when needed
//! 4. Properly verify authorities and relationships
//! 
//! ## Best Practices
//! - Always verify program IDs for CPI targets
//! - Update state BEFORE external calls
//! - Use reentrancy guards for complex flows
//! - Validate all account relationships

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Secure5555555555555555555555555555555555555");

#[program]
pub mod secure_cpi {
    use super::*;

    /// ✅ SECURE: CPI with verified program ID
    pub fn swap_tokens(
        ctx: Context<SwapTokens>,
        amount_in: u64,
        min_amount_out: u64,
    ) -> Result<()> {
        // ✅ Validate inputs
        require!(amount_in > 0, ErrorCode::InvalidAmount);
        require!(min_amount_out > 0, ErrorCode::InvalidMinOutput);
        
        let pool = &mut ctx.accounts.pool;
        
        // ✅ Validate user has sufficient balance
        require!(
            ctx.accounts.user_token_in.amount >= amount_in,
            ErrorCode::InsufficientBalance
        );
        
        // ✅ Calculate output with checked arithmetic
        let amount_out = calculate_swap_output(
            amount_in,
            pool.reserve_in,
            pool.reserve_out,
        )?;
        
        // ✅ Slippage protection
        require!(
            amount_out >= min_amount_out,
            ErrorCode::SlippageExceeded
        );
        
        // ✅ CEI Pattern: Update state BEFORE CPI
        pool.reserve_in = pool.reserve_in
            .checked_add(amount_in)
            .ok_or(ErrorCode::Overflow)?;
        pool.reserve_out = pool.reserve_out
            .checked_sub(amount_out)
            .ok_or(ErrorCode::Underflow)?;
        pool.total_volume = pool.total_volume
            .checked_add(amount_in)
            .ok_or(ErrorCode::Overflow)?;
        
        // ✅ SECURE: CPI with verified token program
        // Program<'info, Token> ensures this is the real SPL Token program
        
        // Transfer tokens IN from user to pool
        let cpi_accounts_in = Transfer {
            from: ctx.accounts.user_token_in.to_account_info(),
            to: ctx.accounts.pool_token_in.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx_in = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts_in,
        );
        token::transfer(cpi_ctx_in, amount_in)?;
        
        // Transfer tokens OUT from pool to user (using PDA signer)
        let pool_seeds = &[
            b"pool".as_ref(),
            pool.token_in_mint.as_ref(),
            pool.token_out_mint.as_ref(),
            &[pool.bump],
        ];
        let signer_seeds = &[&pool_seeds[..]];
        
        let cpi_accounts_out = Transfer {
            from: ctx.accounts.pool_token_out.to_account_info(),
            to: ctx.accounts.user_token_out.to_account_info(),
            authority: ctx.accounts.pool.to_account_info(),
        };
        let cpi_ctx_out = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts_out,
            signer_seeds,
        );
        token::transfer(cpi_ctx_out, amount_out)?;
        
        emit!(SwapExecuted {
            pool: pool.key(),
            user: ctx.accounts.user.key(),
            amount_in,
            amount_out,
        });
        
        msg!("Swapped {} for {}", amount_in, amount_out);
        Ok(())
    }

    /// ✅ SECURE: Deposit with reentrancy protection
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // ✅ Validate input
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Reentrancy guard check
        require!(!vault.locked, ErrorCode::ReentrancyDetected);
        
        // ✅ Set reentrancy guard
        vault.locked = true;
        
        // ✅ CEI Pattern: Update state BEFORE CPI
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        vault.total_deposited = vault.total_deposited
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        vault.deposit_count = vault.deposit_count
            .checked_add(1)
            .ok_or(ErrorCode::Overflow)?;
        
        // ✅ CPI with verified program
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
        
        emit!(DepositMade {
            vault: vault.key(),
            user: ctx.accounts.user.key(),
            amount,
            new_balance: vault.balance,
        });
        
        msg!("Deposited {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ✅ SECURE: Withdraw with proper authority verification
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // ✅ Validate input
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Check balance
        require!(
            vault.balance >= amount,
            ErrorCode::InsufficientBalance
        );
        
        // ✅ Reentrancy guard
        require!(!vault.locked, ErrorCode::ReentrancyDetected);
        vault.locked = true;
        
        // ✅ CEI: Update state first
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;
        vault.total_withdrawn = vault.total_withdrawn
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        // ✅ CPI with PDA signer
        let authority_key = ctx.accounts.authority.key();
        let vault_seeds = &[
            b"vault".as_ref(),
            authority_key.as_ref(),
            &[vault.bump],
        ];
        let signer_seeds = &[&vault_seeds[..]];
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_tokens.to_account_info(),
            to: ctx.accounts.user_tokens.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        token::transfer(cpi_ctx, amount)?;
        
        // ✅ Release lock
        let vault = &mut ctx.accounts.vault;
        vault.locked = false;
        
        emit!(WithdrawalMade {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
            amount,
            remaining_balance: vault.balance,
        });
        
        Ok(())
    }
}

/// Calculate swap output using constant product formula
fn calculate_swap_output(
    amount_in: u64,
    reserve_in: u64,
    reserve_out: u64,
) -> Result<u64> {
    // x * y = k (constant product)
    // (x + dx) * (y - dy) = k
    // dy = y * dx / (x + dx)
    
    let numerator = (amount_in as u128)
        .checked_mul(reserve_out as u128)
        .ok_or(ErrorCode::Overflow)?;
    
    let denominator = (reserve_in as u128)
        .checked_add(amount_in as u128)
        .ok_or(ErrorCode::Overflow)?;
    
    let amount_out = numerator
        .checked_div(denominator)
        .ok_or(ErrorCode::Overflow)?;
    
    require!(
        amount_out <= u64::MAX as u128,
        ErrorCode::OutputTooLarge
    );
    
    Ok(amount_out as u64)
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ Verify token account ownership and mint
    #[account(
        mut,
        constraint = user_token_in.owner == user.key() @ ErrorCode::InvalidOwner,
        constraint = user_token_in.mint == pool.token_in_mint @ ErrorCode::MintMismatch
    )]
    pub user_token_in: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = user_token_out.owner == user.key() @ ErrorCode::InvalidOwner,
        constraint = user_token_out.mint == pool.token_out_mint @ ErrorCode::MintMismatch
    )]
    pub user_token_out: Account<'info, TokenAccount>,
    
    // ✅ Verify pool PDA and token accounts
    #[account(
        mut,
        seeds = [
            b"pool",
            pool.token_in_mint.as_ref(),
            pool.token_out_mint.as_ref()
        ],
        bump = pool.bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(
        mut,
        constraint = pool_token_in.owner == pool.key() @ ErrorCode::InvalidOwner,
        constraint = pool_token_in.mint == pool.token_in_mint @ ErrorCode::MintMismatch
    )]
    pub pool_token_in: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = pool_token_out.owner == pool.key() @ ErrorCode::InvalidOwner,
        constraint = pool_token_out.mint == pool.token_out_mint @ ErrorCode::MintMismatch
    )]
    pub pool_token_out: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Program<'info, Token> verifies this is SPL Token
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        mut,
        constraint = user_tokens.owner == user.key() @ ErrorCode::InvalidOwner
    )]
    pub user_tokens: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(
        mut,
        constraint = vault_tokens.owner == vault.key() @ ErrorCode::InvalidOwner
    )]
    pub vault_tokens: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: Signer<'info>,
    
    #[account(
        mut,
        constraint = user_tokens.owner == authority.key() @ ErrorCode::InvalidOwner
    )]
    pub user_tokens: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(
        mut,
        constraint = vault_tokens.owner == vault.key() @ ErrorCode::InvalidOwner
    )]
    pub vault_tokens: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub token_in_mint: Pubkey,
    pub token_out_mint: Pubkey,
    pub reserve_in: u64,
    pub reserve_out: u64,
    pub total_volume: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub total_deposited: u64,
    pub total_withdrawn: u64,
    pub deposit_count: u64,
    pub bump: u8,
    pub locked: bool,  // ✅ Reentrancy guard
}

#[event]
pub struct SwapExecuted {
    pub pool: Pubkey,
    pub user: Pubkey,
    pub amount_in: u64,
    pub amount_out: u64,
}

#[event]
pub struct DepositMade {
    pub vault: Pubkey,
    pub user: Pubkey,
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

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Invalid minimum output")]
    InvalidMinOutput,
    #[msg("Insufficient balance")]
    InsufficientBalance,
    #[msg("Slippage exceeded")]
    SlippageExceeded,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
    #[msg("Output too large")]
    OutputTooLarge,
    #[msg("Invalid account owner")]
    InvalidOwner,
    #[msg("Token mint mismatch")]
    MintMismatch,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Reentrancy detected")]
    ReentrancyDetected,
}

// ============================================================================
// SECURITY ANALYSIS
// ============================================================================
//
// Why the attacks from vulnerable_cpi.rs FAIL here:
//
// FAKE PROGRAM ATTACK BLOCKED:
// ----------------------------
// 1. Program<'info, Token> verifies program ID
// 2. Anchor checks: token_program.key() == spl_token::ID
// 3. Attacker's fake program has different ID
// 4. Transaction fails with "Invalid program id"
//
// REENTRANCY ATTACK BLOCKED:
// --------------------------
// 1. Reentrancy guard: require!(!vault.locked)
// 2. Lock set BEFORE any external calls
// 3. If callback tries to re-enter:
//    - vault.locked == true
//    - require! fails
//    - Reentrant call reverts
// 4. Lock released only after CPI completes
//
// Additionally, CEI pattern means:
// - State updated BEFORE CPI
// - Even without lock, reentrant call sees updated state
// - No stale state to exploit
//
// AUTHORITY BYPASS BLOCKED:
// -------------------------
// 1. has_one = authority constraint
// 2. PDA seeds include authority
// 3. Attacker can't pass pool they don't own
// 4. Transaction fails with "Unauthorized"
