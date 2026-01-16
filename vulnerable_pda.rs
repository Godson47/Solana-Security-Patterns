//! # Vulnerable PDA Security Example
//! 
//! This program demonstrates vulnerabilities from improper PDA seed usage.
//! 
//! ## Vulnerabilities
//! 1. **Insufficient Seeds**: Only using user-controlled data, allowing collisions
//! 2. **Missing PDA Verification**: Not verifying PDA derivation in instructions
//! 3. **Predictable Seeds**: Using sequential or easily guessable values
//! 
//! ## Attack Vectors
//! 1. Create vault with common name, wait for victim to collide
//! 2. Pre-create vaults for common names, steal deposits
//! 3. Pass manipulated accounts that aren't properly derived
//! 
//! ## DO NOT USE IN PRODUCTION

use anchor_lang::prelude::*;

declare_id!("Vuln444444444444444444444444444444444444444");

#[program]
pub mod vulnerable_pda {
    use super::*;

    /// ❌ VULNERABLE: Create vault with insufficient seeds
    /// 
    /// Attack scenario:
    /// 1. Attacker creates vault named "savings"
    /// 2. Victim tries to create vault named "savings"
    /// 3. Same PDA is derived (collision!)
    /// 4. Victim's transaction fails OR overwrites attacker's vault
    /// 5. Either way, attacker can exploit this
    pub fn create_vault(
        ctx: Context<CreateVault>,
        vault_name: String,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.name = vault_name.clone();
        
        msg!("Created vault: {}", vault_name);
        Ok(())
    }

    /// ❌ VULNERABLE: Withdraw without PDA verification
    /// 
    /// Attack scenario:
    /// 1. Attacker creates a fake vault account (not a PDA)
    /// 2. Sets authority to match their pubkey
    /// 3. Passes this fake account to withdraw
    /// 4. No PDA verification, so it's accepted
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ Only checks authority, not PDA derivation!
        require_keys_eq!(
            vault.authority,
            ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );
        
        vault.balance = vault.balance.checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        
        msg!("Withdrew {} from vault", amount);
        Ok(())
    }

    /// ❌ VULNERABLE: Deposit to any account claiming to be a vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ No verification that this is a legitimate vault PDA
        vault.balance = vault.balance.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        msg!("Deposited {} to vault", amount);
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(vault_name: String)]
pub struct CreateVault<'info> {
    // ❌ VULNERABLE: Seeds only use vault_name
    // Two different users creating "savings" vault will collide!
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", vault_name.as_bytes()],  // ❌ Missing user pubkey!
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // ❌ VULNERABLE: No seeds constraint to verify PDA derivation
    // Attacker can pass any account with matching authority field
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    // ❌ VULNERABLE: No PDA verification
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub depositor: Signer<'info>,
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
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Overflow")]
    Overflow,
}

// ============================================================================
// ATTACK DEMONSTRATIONS
// ============================================================================
//
// COLLISION ATTACK:
// -----------------
// 1. Attacker calls create_vault("main")
//    - PDA derived from: ["vault", "main"]
//    - Attacker is set as authority
//
// 2. Victim calls create_vault("main")
//    - Same PDA derived from: ["vault", "main"]
//    - Transaction fails (account already exists)
//    - OR if using init_if_needed, overwrites attacker's data
//
// 3. If victim deposits to "main" vault thinking it's theirs:
//    - Funds go to attacker-controlled vault
//    - Attacker withdraws victim's funds
//
// PRE-CREATION ATTACK:
// --------------------
// 1. Attacker predicts common vault names: "savings", "main", "default", etc.
// 2. Attacker creates vaults for all common names
// 3. Attacker waits for victims to deposit
// 4. Attacker drains all deposits
//
// FAKE ACCOUNT ATTACK:
// --------------------
// 1. Attacker creates a regular account (not PDA)
// 2. Writes Vault struct data with attacker as authority
// 3. Calls withdraw with this fake account
// 4. No PDA verification, withdrawal succeeds
