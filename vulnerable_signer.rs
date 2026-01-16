//! # Vulnerable Signer Check Example
//! 
//! This program demonstrates a CRITICAL vulnerability: missing signer verification.
//! 
//! ## Vulnerability
//! The `authority` account is not required to sign the transaction, allowing
//! anyone to pass any public key as the authority and perform unauthorized actions.
//! 
//! ## Attack Vector
//! 1. Attacker finds a vault with funds
//! 2. Attacker reads the vault's authority pubkey from on-chain data
//! 3. Attacker creates a withdraw transaction, passing victim's pubkey as authority
//! 4. Since no signature is required, the transaction succeeds
//! 5. Attacker drains the vault
//! 
//! ## Impact
//! - Complete bypass of access control
//! - Unauthorized fund withdrawal
//! - Total loss of user funds
//! 
//! ## DO NOT USE IN PRODUCTION

use anchor_lang::prelude::*;

declare_id!("Vuln111111111111111111111111111111111111111");

#[program]
pub mod vulnerable_signer {
    use super::*;

    /// Initialize a new vault for a user
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        
        msg!("Vault initialized for authority: {}", vault.authority);
        Ok(())
    }

    /// Deposit funds into the vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // This is fine - anyone can deposit
        vault.balance = vault.balance.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        msg!("Deposited {} lamports. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// ❌ VULNERABLE: Withdraw funds from the vault
    /// 
    /// This function is CRITICALLY VULNERABLE because:
    /// 1. The `authority` account is NOT required to sign
    /// 2. Anyone can pass ANY pubkey as the authority
    /// 3. The only "check" is comparing pubkeys, but that's useless without signature
    /// 
    /// An attacker can:
    /// - Read the vault's authority from on-chain data
    /// - Pass that pubkey as the authority account
    /// - Withdraw all funds without the real authority's signature
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ THIS CHECK IS USELESS WITHOUT SIGNER VERIFICATION!
        // The attacker simply passes the correct pubkey - they don't need to sign
        require_keys_eq!(
            ctx.accounts.authority.key(),
            vault.authority,
            ErrorCode::Unauthorized
        );
        
        // Attacker can drain the entire vault
        vault.balance = vault.balance.checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        
        msg!("Withdrew {} lamports. New balance: {}", amount, vault.balance);
        
        // In a real program, this would transfer SOL/tokens to the attacker
        // The attacker specifies their own account as the recipient
        
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
    pub authority: Signer<'info>,  // Signer here is fine for init
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub depositor: Signer<'info>,  // Anyone can deposit
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // ❌ VULNERABLE: This is NOT a Signer!
    // Using AccountInfo means NO signature verification
    // The transaction will succeed even if this account didn't sign
    /// CHECK: This SHOULD be verified as a signer but ISN'T
    pub authority: AccountInfo<'info>,
    
    // The attacker would add their own account here to receive funds
    // #[account(mut)]
    // pub recipient: AccountInfo<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    /// The authority who can withdraw from this vault
    pub authority: Pubkey,
    /// Current balance in the vault
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access attempt")]
    Unauthorized,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Arithmetic overflow")]
    Overflow,
}

// ============================================================================
// ATTACK DEMONSTRATION (Pseudocode)
// ============================================================================
//
// async function exploitVulnerableSigner(
//     connection: Connection,
//     attackerKeypair: Keypair,
//     victimVaultAddress: PublicKey
// ) {
//     // Step 1: Read the vault data to get the authority pubkey
//     const vaultAccount = await program.account.vault.fetch(victimVaultAddress);
//     const victimAuthority = vaultAccount.authority;
//     
//     // Step 2: Create withdraw instruction
//     // Note: We pass victimAuthority but DON'T need their signature!
//     const tx = await program.methods
//         .withdraw(vaultAccount.balance)  // Withdraw everything
//         .accounts({
//             vault: victimVaultAddress,
//             authority: victimAuthority,  // Victim's pubkey, no signature needed!
//         })
//         .signers([attackerKeypair])  // Only attacker signs
//         .rpc();
//     
//     console.log("Drained vault! TX:", tx);
// }
