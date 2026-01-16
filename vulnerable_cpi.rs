//! # Vulnerable CPI Security Example
//! 
//! This program demonstrates vulnerabilities in Cross-Program Invocation (CPI).
//! 
//! ## Vulnerabilities
//! 1. **Unverified Program**: Calling a program without verifying its ID
//! 2. **Reentrancy**: Updating state after external calls
//! 3. **Privilege Escalation**: Incorrect signer seed handling
//! 
//! ## Attack Vectors
//! 1. Pass malicious program that steals funds
//! 2. Re-enter during callback to exploit stale state
//! 3. Escalate privileges through CPI
//! 
//! ## DO NOT USE IN PRODUCTION

use anchor_lang::prelude::*;

declare_id!("Vuln555555555555555555555555555555555555555");

#[program]
pub mod vulnerable_cpi {
    use super::*;

    /// ❌ VULNERABLE: CPI to unverified program
    /// 
    /// Attack scenario:
    /// 1. Attacker deploys malicious "token program"
    /// 2. Malicious program's transfer does nothing (or steals funds)
    /// 3. Attacker calls swap with malicious program
    /// 4. Pool state updated (thinks it received tokens)
    /// 5. Attacker gets output tokens for free
    pub fn swap_tokens(
        ctx: Context<SwapTokens>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // ❌ VULNERABLE: Calling unverified program!
        // Attacker can pass ANY program ID here
        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.token_program.key(),  // ❌ Not verified!
            accounts: vec![
                AccountMeta::new(ctx.accounts.user_token_in.key(), false),
                AccountMeta::new(ctx.accounts.pool_token_in.key(), false),
                AccountMeta::new_readonly(ctx.accounts.user.key(), true),
            ],
            data: vec![3, 0, 0, 0, 0, 0, 0, 0],  // Fake transfer instruction
        };
        
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.user_token_in.to_account_info(),
                ctx.accounts.pool_token_in.to_account_info(),
                ctx.accounts.user.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        
        // ❌ State updated assuming transfer succeeded
        // But malicious program might not have done anything!
        pool.total_swapped = pool.total_swapped.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        msg!("Swapped {} tokens", amount);
        Ok(())
    }

    /// ❌ VULNERABLE: Reentrancy through state update after CPI
    /// 
    /// Attack scenario:
    /// 1. Attacker deploys malicious token with callback
    /// 2. Token's transfer calls back into this program
    /// 3. State not yet updated, attacker re-enters
    /// 4. Attacker drains funds through repeated calls
    pub fn deposit_with_callback(
        ctx: Context<DepositWithCallback>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ VULNERABLE: External call BEFORE state update!
        // Malicious callback can re-enter while state is stale
        
        // Simulate external call (in real code, this would be CPI)
        msg!("Making external call...");
        
        // If the external call triggers a callback that calls deposit again:
        // - vault.balance is still the OLD value
        // - Attacker can deposit multiple times with same funds
        
        // ❌ State update AFTER external call - REENTRANCY RISK!
        vault.balance = vault.balance.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        msg!("Deposited {}. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ❌ VULNERABLE: Incorrect authority check for CPI
    /// 
    /// Attack scenario:
    /// 1. Attacker finds a way to pass wrong authority
    /// 2. CPI succeeds with attacker's authority
    /// 3. Attacker gains unauthorized access
    pub fn transfer_from_pool(
        ctx: Context<TransferFromPool>,
        amount: u64,
    ) -> Result<()> {
        // ❌ VULNERABLE: Not verifying pool authority matches signer
        // Attacker might pass a pool they don't own
        
        msg!("Transferring {} from pool", amount);
        
        // In real code, CPI would happen here
        // But authority isn't properly verified
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    /// CHECK: User's token account
    #[account(mut)]
    pub user_token_in: AccountInfo<'info>,
    
    /// CHECK: Pool's token account
    #[account(mut)]
    pub pool_token_in: AccountInfo<'info>,
    
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    // ❌ VULNERABLE: No verification this is the real token program!
    // Attacker can pass their own malicious program
    /// CHECK: Should be token program but isn't verified
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DepositWithCallback<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct TransferFromPool<'info> {
    // ❌ VULNERABLE: No has_one constraint
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub total_swapped: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Overflow")]
    Overflow,
}

// ============================================================================
// ATTACK DEMONSTRATIONS
// ============================================================================
//
// FAKE PROGRAM ATTACK:
// --------------------
// 1. Attacker deploys FakeTokenProgram:
//    - transfer() does nothing, just returns Ok
//    
// 2. Attacker calls swap_tokens:
//    - Passes FakeTokenProgram as token_program
//    - No tokens actually transferred
//    - Pool state updated as if swap happened
//    
// 3. Attacker receives output tokens without paying input
//
// REENTRANCY ATTACK:
// ------------------
// 1. Attacker deploys MaliciousToken:
//    - transfer() calls back to deposit_with_callback
//    
// 2. Attack flow:
//    a. Attacker calls deposit(100)
//    b. External call to MaliciousToken.transfer()
//    c. MaliciousToken calls deposit(100) again
//    d. vault.balance still at old value, check passes
//    e. Inner deposit completes, balance += 100
//    f. Outer deposit completes, balance += 100
//    g. Attacker deposited 100 but balance shows 200
//    
// 3. Repeat until drained
//
// AUTHORITY BYPASS:
// -----------------
// 1. Attacker finds pool with funds
// 2. Calls transfer_from_pool with:
//    - pool: victim's pool
//    - authority: attacker's keypair
// 3. No has_one check, authority mismatch not caught
// 4. Attacker drains pool
