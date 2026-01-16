//! # Secure Signer Check Example
//! 
//! This program demonstrates the CORRECT way to verify signers in Solana programs.
//! 
//! ## Security Measures
//! 1. Use `Signer<'info>` type for accounts that must authorize actions
//! 2. Add constraint checks to verify the signer matches stored authority
//! 3. Use `has_one` constraint for automatic authority matching
//! 4. Implement defense-in-depth with multiple validation layers
//! 
//! ## Why This Works
//! - Solana runtime enforces that `Signer` accounts must have signed the transaction
//! - The constraint provides defense-in-depth
//! - Even if an attacker knows the authority pubkey, they can't sign without the private key

use anchor_lang::prelude::*;

declare_id!("Secure1111111111111111111111111111111111111");

#[program]
pub mod secure_signer {
    use super::*;

    /// Initialize a new vault for a user
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.total_withdrawn = 0;
        vault.withdrawal_count = 0;
        
        emit!(VaultInitialized {
            vault: vault.key(),
            authority: vault.authority,
        });
        
        msg!("Vault initialized for authority: {}", vault.authority);
        Ok(())
    }

    /// Deposit funds into the vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // Validate amount
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        emit!(DepositMade {
            vault: vault.key(),
            depositor: ctx.accounts.depositor.key(),
            amount,
            new_balance: vault.balance,
        });
        
        msg!("Deposited {} lamports. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ✅ SECURE: Withdraw funds from the vault
    /// 
    /// This function is SECURE because:
    /// 1. `authority` uses `Signer<'info>` - Anchor verifies signature
    /// 2. `has_one = authority` constraint verifies it matches vault's stored authority
    /// 3. Additional explicit check provides defense-in-depth
    /// 
    /// An attacker CANNOT:
    /// - Pass someone else's pubkey without their signature
    /// - Forge a signature without the private key
    /// - Bypass the has_one constraint
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // Validate amount
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Defense-in-depth: Explicit authority check
        // This is redundant with has_one but provides extra safety
        require_keys_eq!(
            ctx.accounts.authority.key(),
            vault.authority,
            ErrorCode::UnauthorizedAuthority
        );
        
        // Check sufficient balance
        require!(
            vault.balance >= amount,
            ErrorCode::InsufficientFunds
        );
        
        // Update state
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;
        vault.total_withdrawn = vault.total_withdrawn
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        vault.withdrawal_count = vault.withdrawal_count
            .checked_add(1)
            .ok_or(ErrorCode::Overflow)?;
        
        emit!(WithdrawalMade {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
            amount,
            remaining_balance: vault.balance,
        });
        
        msg!("Withdrew {} lamports. Remaining balance: {}", amount, vault.balance);
        
        // In production: Transfer SOL/tokens here
        // The transfer would go to an account owned by the verified signer
        
        Ok(())
    }

    /// ✅ SECURE: Transfer authority to a new owner
    /// 
    /// Both current and new authority must sign
    pub fn transfer_authority(ctx: Context<TransferAuthority>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let old_authority = vault.authority;
        
        vault.authority = ctx.accounts.new_authority.key();
        
        emit!(AuthorityTransferred {
            vault: vault.key(),
            old_authority,
            new_authority: vault.authority,
        });
        
        msg!(
            "Authority transferred from {} to {}", 
            old_authority, 
            vault.authority
        );
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
    // ✅ SECURE: has_one constraint verifies authority matches
    #[account(
        mut,
        has_one = authority @ ErrorCode::UnauthorizedAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    // ✅ SECURE: Signer<'info> ensures this account signed the transaction
    // The transaction will FAIL if authority didn't sign
    // Anchor automatically checks: account.is_signer == true
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferAuthority<'info> {
    #[account(
        mut,
        has_one = authority @ ErrorCode::UnauthorizedAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    // ✅ Current authority must sign
    pub authority: Signer<'info>,
    
    // ✅ New authority must also sign (proves they accept ownership)
    pub new_authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    /// The authority who can withdraw from this vault
    pub authority: Pubkey,
    /// Current balance in the vault
    pub balance: u64,
    /// Total amount ever withdrawn (for analytics)
    pub total_withdrawn: u64,
    /// Number of withdrawals made
    pub withdrawal_count: u64,
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
pub struct AuthorityTransferred {
    pub vault: Pubkey,
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized authority for this vault")]
    UnauthorizedAuthority,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Invalid amount - must be greater than zero")]
    InvalidAmount,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
}

// ============================================================================
// SECURITY ANALYSIS
// ============================================================================
//
// Why the attack from vulnerable_signer.rs FAILS here:
//
// 1. Attacker tries to call withdraw with victim's pubkey as authority
// 2. Anchor checks: Is authority.is_signer == true?
// 3. Since attacker didn't sign with victim's private key, is_signer == false
// 4. Transaction fails with "Signature verification failed"
//
// The attacker would need the victim's private key to sign, which they don't have.
//
// Additional protections:
// - has_one constraint ensures the signer matches the stored authority
// - Events provide audit trail for monitoring
// - Explicit balance checks prevent edge cases
// - Checked arithmetic prevents overflow/underflow
