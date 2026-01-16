//! # Secure PDA Security Example
//! 
//! This program demonstrates CORRECT PDA usage in Solana programs.
//! 
//! ## Security Measures
//! 1. Include user pubkey in PDA seeds for uniqueness
//! 2. Verify PDA derivation in all instructions
//! 3. Store and validate bump seeds
//! 4. Use has_one for authority checks
//! 
//! ## Why This Works
//! - Each user gets their own unique PDA even with same name
//! - PDA derivation is verified on every access
//! - Attackers cannot create colliding accounts

use anchor_lang::prelude::*;

declare_id!("Secure4444444444444444444444444444444444444");

#[program]
pub mod secure_pda {
    use super::*;

    /// ✅ SECURE: Create vault with user-bound PDA
    /// 
    /// Seeds include authority pubkey, so each user gets unique PDA
    /// even if they use the same vault name
    pub fn create_vault(
        ctx: Context<CreateVault>,
        vault_name: String,
    ) -> Result<()> {
        // Validate name length
        require!(
            vault_name.len() > 0 && vault_name.len() <= 32,
            ErrorCode::InvalidVaultName
        );
        
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.name = vault_name.clone();
        vault.bump = ctx.bumps.vault;  // ✅ Store bump for efficient re-derivation
        vault.created_at = Clock::get()?.unix_timestamp;
        
        emit!(VaultCreated {
            vault: vault.key(),
            authority: vault.authority,
            name: vault_name,
        });
        
        msg!("Created vault '{}' for user {}", vault.name, vault.authority);
        Ok(())
    }

    /// ✅ SECURE: Withdraw with full PDA verification
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        require!(
            vault.balance >= amount,
            ErrorCode::InsufficientFunds
        );
        
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;
        
        emit!(WithdrawalMade {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
            amount,
            remaining_balance: vault.balance,
        });
        
        msg!("Withdrew {} from vault '{}'. Remaining: {}", 
            amount, vault.name, vault.balance);
        Ok(())
    }

    /// ✅ SECURE: Deposit with PDA verification
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
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
        
        msg!("Deposited {} to vault '{}'. New balance: {}", 
            amount, vault.name, vault.balance);
        Ok(())
    }

    /// ✅ SECURE: Transfer using PDA as signer
    /// 
    /// Demonstrates how to use stored bump for CPI signing
    pub fn transfer_from_vault(
        ctx: Context<TransferFromVault>,
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &ctx.accounts.vault;
        let authority_key = ctx.accounts.authority.key();
        
        require!(
            vault.balance >= amount,
            ErrorCode::InsufficientFunds
        );
        
        // ✅ SECURE: Reconstruct seeds for PDA signing
        let seeds = &[
            b"vault".as_ref(),
            authority_key.as_ref(),
            vault.name.as_bytes(),
            &[vault.bump],
        ];
        let _signer_seeds = &[&seeds[..]];
        
        // In production, use signer_seeds for CPI:
        // let cpi_ctx = CpiContext::new_with_signer(
        //     ctx.accounts.token_program.to_account_info(),
        //     Transfer { ... },
        //     signer_seeds,
        // );
        // token::transfer(cpi_ctx, amount)?;
        
        msg!("Transfer {} from vault PDA authorized", amount);
        Ok(())
    }

    /// ✅ SECURE: Close vault and reclaim rent
    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        let vault = &ctx.accounts.vault;
        
        // Ensure vault is empty before closing
        require!(
            vault.balance == 0,
            ErrorCode::VaultNotEmpty
        );
        
        emit!(VaultClosed {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
        });
        
        msg!("Closed vault '{}'", vault.name);
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(vault_name: String)]
pub struct CreateVault<'info> {
    // ✅ SECURE: Seeds include authority pubkey
    // Each user gets their own unique vault PDA
    // ["vault", user_pubkey, "savings"] is unique per user
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [
            b"vault",
            authority.key().as_ref(),  // ✅ User-specific!
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
pub struct Withdraw<'info> {
    // ✅ SECURE: Full PDA verification with seeds
    #[account(
        mut,
        seeds = [
            b"vault",
            authority.key().as_ref(),
            vault.name.as_bytes()
        ],
        bump = vault.bump,  // ✅ Use stored bump
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    // ✅ SECURE: PDA verification ensures legitimate vault
    #[account(
        mut,
        seeds = [
            b"vault",
            vault.authority.as_ref(),  // Use stored authority for derivation
            vault.name.as_bytes()
        ],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,
    
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferFromVault<'info> {
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
pub struct CloseVault<'info> {
    #[account(
        mut,
        seeds = [
            b"vault",
            authority.key().as_ref(),
            vault.name.as_bytes()
        ],
        bump = vault.bump,
        has_one = authority @ ErrorCode::Unauthorized,
        close = authority  // ✅ Return rent to authority
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    /// The authority who owns this vault
    pub authority: Pubkey,
    /// Current balance
    pub balance: u64,
    /// Vault name (part of PDA seeds)
    #[max_len(32)]
    pub name: String,
    /// Stored bump for efficient PDA operations
    pub bump: u8,
    /// Creation timestamp
    pub created_at: i64,
}

#[event]
pub struct VaultCreated {
    pub vault: Pubkey,
    pub authority: Pubkey,
    pub name: String,
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
pub struct VaultClosed {
    pub vault: Pubkey,
    pub authority: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access to vault")]
    Unauthorized,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Invalid amount - must be greater than zero")]
    InvalidAmount,
    #[msg("Invalid vault name - must be 1-32 characters")]
    InvalidVaultName,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
    #[msg("Vault must be empty before closing")]
    VaultNotEmpty,
}

// ============================================================================
// SECURITY ANALYSIS
// ============================================================================
//
// Why the attacks from vulnerable_pda.rs FAIL here:
//
// COLLISION ATTACK BLOCKED:
// -------------------------
// User A creates vault "savings":
//   PDA = derive(["vault", UserA_pubkey, "savings"])
//
// User B creates vault "savings":
//   PDA = derive(["vault", UserB_pubkey, "savings"])
//
// Different PDAs! No collision possible.
//
// PRE-CREATION ATTACK BLOCKED:
// ----------------------------
// Attacker cannot pre-create vaults for victims because:
// 1. PDA includes victim's pubkey
// 2. Attacker doesn't know victim's pubkey in advance
// 3. Even if they did, they can't create PDA for another user
//    (init requires authority to sign and pay)
//
// FAKE ACCOUNT ATTACK BLOCKED:
// ----------------------------
// Attacker creates fake account and calls withdraw:
// 1. seeds constraint verifies PDA derivation
// 2. Fake account won't match derived PDA
// 3. Transaction fails with "seeds constraint violated"
//
// BUMP MANIPULATION BLOCKED:
// --------------------------
// Attacker tries to use different bump:
// 1. bump = vault.bump uses stored value
// 2. Can't pass arbitrary bump
// 3. Derivation must match exactly
