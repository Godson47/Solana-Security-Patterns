//! # Vulnerable Account Matching Example
//! 
//! This program demonstrates vulnerabilities from missing account relationship verification.
//! 
//! ## Vulnerabilities
//! 1. **No Owner Verification**: Token accounts not verified to belong to signer
//! 2. **No Mint Verification**: Token mints not checked
//! 3. **No Relationship Verification**: Account relationships not validated
//! 
//! ## Attack Vectors
//! 1. Pass victim's token account as source
//! 2. Deposit worthless tokens, get valuable pool shares
//! 3. Claim rewards from wrong vault
//! 
//! ## DO NOT USE IN PRODUCTION

use anchor_lang::prelude::*;

declare_id!("Vuln666666666666666666666666666666666666666");

#[program]
pub mod vulnerable_matching {
    use super::*;

    /// ❌ VULNERABLE: Transfer without ownership verification
    /// 
    /// Attack scenario:
    /// 1. Attacker finds victim's token account with funds
    /// 2. Attacker calls transfer with victim's account as source
    /// 3. No ownership check, transfer proceeds
    /// 4. Attacker steals victim's tokens
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64,
    ) -> Result<()> {
        // ❌ VULNERABLE: from_account might not belong to authority!
        // Attacker can pass any token account as source
        
        msg!("Transferring {} tokens", amount);
        
        // In real code, CPI transfer would happen here
        // But from_account ownership isn't verified!
        
        Ok(())
    }

    /// ❌ VULNERABLE: Deposit without mint verification
    /// 
    /// Attack scenario:
    /// 1. Pool accepts USDC deposits
    /// 2. Attacker creates worthless "FAKE" token
    /// 3. Attacker deposits FAKE tokens (no mint check)
    /// 4. Attacker receives pool shares worth real USDC
    /// 5. Attacker redeems shares for real USDC
    pub fn deposit_to_pool(
        ctx: Context<DepositToPool>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // ❌ VULNERABLE: user_tokens might be for wrong mint!
        // No verification that token mint matches pool's expected mint
        
        pool.total_deposits = pool.total_deposits.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        // Calculate shares (simplified)
        let shares = amount;  // 1:1 for simplicity
        
        msg!("Deposited {} tokens, received {} shares", amount, shares);
        
        // In real code, transfer and mint shares would happen
        // But mint isn't verified!
        
        Ok(())
    }

    /// ❌ VULNERABLE: Claim rewards without relationship verification
    /// 
    /// Attack scenario:
    /// 1. Attacker finds pool with large reward vault
    /// 2. Attacker creates fake staking account
    /// 3. Sets pending_rewards to maximum
    /// 4. Calls claim with real pool's reward vault
    /// 5. Drains entire reward vault
    pub fn claim_rewards(
        ctx: Context<ClaimRewards>,
    ) -> Result<()> {
        let staking = &ctx.accounts.staking_account;
        let rewards = staking.pending_rewards;
        
        // ❌ VULNERABLE: reward_vault might not be the pool's vault!
        // No verification of relationship between staking account and vault
        
        require!(rewards > 0, ErrorCode::NoRewards);
        
        msg!("Claiming {} rewards", rewards);
        
        // In real code, transfer from reward_vault would happen
        // But vault relationship isn't verified!
        
        Ok(())
    }

    /// ❌ VULNERABLE: Stake without verifying pool relationship
    pub fn stake(
        ctx: Context<Stake>,
        amount: u64,
    ) -> Result<()> {
        let staking = &mut ctx.accounts.staking_account;
        
        // ❌ VULNERABLE: No verification that staking account belongs to this pool
        // Attacker can use staking account from different pool
        
        staking.amount = staking.amount.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        msg!("Staked {} tokens", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    // ❌ VULNERABLE: No owner constraint
    // Anyone can pass any token account
    /// CHECK: Should verify ownership
    #[account(mut)]
    pub from_account: AccountInfo<'info>,
    
    /// CHECK: Destination
    #[account(mut)]
    pub to_account: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct DepositToPool<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ❌ VULNERABLE: No mint constraint
    // User can deposit any token type
    /// CHECK: Should verify mint
    #[account(mut)]
    pub user_tokens: AccountInfo<'info>,
    
    // ❌ VULNERABLE: No relationship to pool verified
    /// CHECK: Should verify pool relationship
    #[account(mut)]
    pub pool_tokens: AccountInfo<'info>,
    
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    pub user: Signer<'info>,
    
    // ❌ VULNERABLE: No verification of ownership or pool relationship
    #[account(mut)]
    pub staking_account: Account<'info, StakingAccount>,
    
    // ❌ VULNERABLE: No verification this is the correct reward vault
    /// CHECK: Should verify this is pool's reward vault
    #[account(mut)]
    pub reward_vault: AccountInfo<'info>,
    
    /// CHECK: User's reward account
    #[account(mut)]
    pub user_reward_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    pub user: Signer<'info>,
    
    // ❌ VULNERABLE: No pool relationship verification
    #[account(mut)]
    pub staking_account: Account<'info, StakingAccount>,
    
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub token_mint: Pubkey,
    pub reward_vault: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct StakingAccount {
    pub owner: Pubkey,
    pub pool: Pubkey,
    pub amount: u64,
    pub pending_rewards: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Overflow")]
    Overflow,
    #[msg("No rewards to claim")]
    NoRewards,
}

// ============================================================================
// ATTACK DEMONSTRATIONS
// ============================================================================
//
// TOKEN THEFT ATTACK:
// -------------------
// 1. Attacker finds victim's USDC token account
// 2. Attacker calls transfer_tokens:
//    - from_account: victim's token account
//    - to_account: attacker's token account
//    - authority: attacker (signs transaction)
// 3. No ownership verification!
// 4. Transfer proceeds, victim's tokens stolen
//
// FAKE TOKEN DEPOSIT:
// -------------------
// 1. Pool accepts USDC (mint: USDC_MINT)
// 2. Attacker creates FAKE token (mint: FAKE_MINT)
// 3. Attacker calls deposit_to_pool:
//    - user_tokens: attacker's FAKE token account
//    - pool_tokens: pool's USDC account
//    - amount: 1,000,000
// 4. No mint verification!
// 5. Pool records 1M deposit, gives attacker shares
// 6. Attacker redeems shares for real USDC
//
// REWARD THEFT:
// -------------
// 1. Attacker creates fake StakingAccount:
//    - owner: attacker
//    - pool: any pool with rewards
//    - pending_rewards: u64::MAX
// 2. Attacker calls claim_rewards:
//    - staking_account: fake account
//    - reward_vault: real pool's reward vault
// 3. No relationship verification!
// 4. Entire reward vault drained to attacker
