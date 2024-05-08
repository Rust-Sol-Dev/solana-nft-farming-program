use crate::constants::*;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{sysvar, clock, program_option::COption};
use anchor_spl::token::{self, TokenAccount, Token, Mint};
use std::convert::Into;
use std::convert::TryInto;

declare_id!("TeSTKchdpa2FKNV6gYNAENpququb3aT2r1pD41tZw36");

mod constants {
    pub const TOKEN_MINT_PUBKEY: &str = "tEsTL8G8drugWztoCKrPpEAXV21qEajfHg4q45KYs6s";
    pub const X_STEP_DEPOSIT_REQUIREMENT: u64 = 10_000_000_000_000;
    pub const MIN_DURATION: u64 = 1;
}

const PRECISION: u128 = u64::MAX as u128;

pub fn update_points_balance(
    pool: &mut Account<Pool>,
    user: Option<&mut Box<Account<User>>>,
) -> Result<()> {
    let clock = clock::Clock::get().unwrap();
    if let Some(u) = user {
        u.points_debt = unDebitedPoints(
            u.balance_staked,
            pool.reward_per_token,
            u.last_update_time,
            clock.unix_timestamp.try_into().unwrap(),
        );
    }

    Ok(())
}

pub fn unDebitedPoints(
    balance_staked: u128,
    reward_per_token: u128,
    user_last_update_at: u128,
    current_timestamp: u128,
) -> u128 {
    if let Some(duration) = current_timestamp.checked_sub(user_last_update_at) {
        if let Some(points_earned) = duration.checked_mul(reward_per_token) {
            if let Some(unDebitedPoints) = points_earned.checked_mul(balance_staked) {
                return unDebitedPoints;
            }
        }
    }
    0
}

#[program]
pub mod nftfarming {
    use super::*;

    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        pool_nonce: u8,
        reward_per_token: u128,
        nft_provider: Pubkey,
    ) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;

        pool.authority = *ctx.accounts.authority.key;
        pool.nonce = pool_nonce;
        pool.staking_mint = *ctx.accounts.staking_mint.key;
        pool.staking_vault = *ctx.accounts.staking_vault.key;
        pool.user_stake_count = 0;
        pool.reward_per_token = reward_per_token;
        pool.nft_provider = nft_provider;

        Ok(())
    }

    pub fn create_user(ctx: Context<CreateUser>, nonce: u8) -> ProgramResult {
        let user = &mut ctx.accounts.user;
        user.pool = *ctx.accounts.pool.to_account_info().key;
        user.owner = *ctx.accounts.owner.key;
        user.points_redeemed = 0;
        user.points_debt = 0;
        user.balance_staked = 0;
        user.nonce = nonce;

        ctx.accounts.pool.user_stake_count = ctx.accounts.pool.user_stake_count.checked_add(1).ok_or(ErrorCode::ArithmeticOverflow)?;

        Ok(())
    }

    pub fn stake(ctx: Context<Stake>, amount: u64) -> ProgramResult {
        if amount == 0 {
            return Err(ErrorCode::AmountMustBeGreaterThanZero.into());
        }

        let pool = &mut ctx.accounts.pool;

        update_points_balance(pool, Some(&mut ctx.accounts.user))?;

        ctx.accounts.user.balance_staked = ctx.accounts.user.balance_staked.checked_sub(amount as u128).ok_or(ErrorCode::ArithmeticUnderflow)?;

        let clock = Clock::get()?;
        ctx.accounts.user.last_update_time = clock.unix_timestamp;

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.stake_from_account.to_account_info(),
                    to: ctx.accounts.staking_vault.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
                },
                &[&[ctx.accounts.pool.to_account_info().key.as_ref(), &[ctx.accounts.pool.nonce]]],
            ),
            amount,
        )?;

        Ok(())
    }

    pub fn unstake(ctx: Context<Stake>, spt_amount: u128) -> ProgramResult {
        if spt_amount == 0 {
            return Err(ErrorCode::AmountMustBeGreaterThanZero.into());
        }

        if ctx.accounts.user.balance_staked < spt_amount {
            return Err(ErrorCode::InsufficientFundUnstake.into());
        }

        let pool = &mut ctx.accounts.pool;

        update_points_balance(pool, Some(&mut ctx.accounts.user))?;

        ctx.accounts.user.balance_staked = ctx.accounts.user.balance_staked.checked_sub(spt_amount).ok_or(ErrorCode::ArithmeticUnderflow)?;

        let clock = Clock::get()?;
        ctx.accounts.user.last_update_time = clock.unix_timestamp;

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.staking_vault.to_account_info(),
                    to: ctx.accounts.stake_from_account.to_account_info(),
                    authority: ctx.accounts.pool_signer.to_account_info(),
                },
                &[&[ctx.accounts.pool.to_account_info().key.as_ref(), &[ctx.accounts.pool.nonce]]],
            ),
            spt_amount.try_into().unwrap(),
        )?;

        Ok(())
    }

    pub fn add_nft(ctx: Context<AddNFT>, price: u128) -> ProgramResult {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.from.to_account_info(),
                    to: ctx.accounts.staking_vault.to_account_info(),
                    authority: ctx.accounts.funder.to_account_info(),
                },
            ),
            1,
        )?;

        ctx.accounts.pool.nfts.push(NFTInfo {
            nft_mint: *ctx.accounts.staking_mint.key,
            nft_vault: *ctx.accounts.staking_vault.key,
            price,
            redeemed: false,
        });

        Ok(())
    }

    pub fn claim_nft(ctx: Context<ClaimNFT>, nft_id: u8) -> ProgramResult {
        let pool = &mut ctx.accounts.pool;

        if pool.nfts[nft_id as usize].redeemed {
            return Err(ErrorCode::NFTClaimed.into());
        }

        if pool.nfts[nft_id as usize].nft_vault != *ctx.accounts.nft_vault.key {
            return Err(ErrorCode::NotMyStakingVault.into());
        }

        update_points_balance(pool, Some(&mut ctx.accounts.user))?;

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.nft_vault.to_account_info(),
                    to: ctx.accounts.receive_vault.to_account_info(),
                    authority: ctx.accounts.pool_signer.to_account_info(),
                },
            ),
            1,
        )?;

        pool.nfts[nft_id as usize].redeemed = true;

        Ok(())
    }
}


#[derive(Accounts)]
#[instruction(pool_nonce: u8)]
pub struct InitializePool<'info> {
    #[account(signer)]
    authority: AccountInfo<'info>,

    #[account(mut)]
    staking_mint: Account<'info, Mint>,

    #[account(
        constraint = staking_vault.owner == *pool_signer.key,
        constraint = staking_vault.close_authority == COption::None,
    )]
    staking_vault: Account<'info, TokenAccount>,

    #[account(
        init,
        seeds = [&pool_signer.key().to_bytes()[..], &[pool_nonce]],
        bump = pool_nonce,
    )]
    pool_signer: Account<'info, Signer>,

    #[account(init, payer = authority, space = 200)] // Adjust space according to your struct size
    pool: Account<'info, Pool>,

    token_program: Program<'info, Token>,
}



#[derive(Accounts)]
pub struct AddNFT<'info> {
    #[account(
        mut, 
        has_one = staking_vault,
    )]
    pool: Box<Account<'info, Pool>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    staking_mint: Box<Account<'info, Mint>>,
    #[account(
        constraint = staking_vault.mint == staking_mint.key(),
        constraint = staking_vault.owner == pool_signer.key(),
        //strangely, spl maintains this on owner reassignment for non-native accounts
        //we don't want to be given an account that someone else could close when empty
        //because in our "pool close" operation we want to assert it is still open
        constraint = staking_vault.close_authority == COption::None,
    )]
    staking_vault: Box<Account<'info, TokenAccount>>,
    
    funder: Signer<'info>,

    #[account(mut)]
    from: Box<Account<'info, TokenAccount>>,

    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimNFT<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut, 
        has_one = staking_vault,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(mut)]
    staking_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    receive_vault: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    nft_vault: Box<Account<'info, TokenAccount>>,

    // User.
    #[account(
        mut,
        has_one = owner,
        has_one = pool,
        seeds = [
            owner.to_account_info().key.as_ref(),
            pool.to_account_info().key.as_ref()
        ],
        bump = user.nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(nonce: u8)]
pub struct CreateUser<'info> {
    // Stake instance.
    #[account(
        mut
    )]
    pool: Box<Account<'info, Pool>>,
    // Member.
    #[account(
        init,
        payer = owner,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    // Misc.
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    // Global accounts for the staking instance.
    #[account(
        mut, 
        has_one = staking_vault,
    )]
    pool: Box<Account<'info, Pool>>,
    #[account(
        mut,
        constraint = staking_vault.owner == *pool_signer.key,
    )]
    staking_vault: Box<Account<'info, TokenAccount>>,

    // User.
    #[account(
        mut, 
        has_one = owner, 
        has_one = pool,
        seeds = [
            owner.key.as_ref(), 
            pool.to_account_info().key.as_ref()
        ],
        bump = user.nonce,
    )]
    user: Box<Account<'info, User>>,
    owner: Signer<'info>,
    #[account(mut)]
    stake_from_account: Box<Account<'info, TokenAccount>>,

    // Program signers.
    #[account(
        seeds = [
            pool.to_account_info().key.as_ref()
        ],
        bump = pool.nonce,
    )]
    pool_signer: UncheckedAccount<'info>,

    // Misc.
    token_program: Program<'info, Token>,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct NFTInfo {
    /// Mint of the NFT
    pub nft_mint: Pubkey,
    /// Vault to store NFT
    pub nft_vault: Pubkey,
    /// Points required to claim the NFT
    pub price: u128,
    /// Redeem Status
    pub redeemed: bool,
}

#[account]
pub struct Pool {
    /// Priviledged account.
    pub authority: Pubkey,
    /// Mint of the token that can be staked.
    pub staking_mint: Pubkey,
    /// Vault to store staked tokens.
    pub staking_vault: Pubkey,
    /// Users staked
    pub user_stake_count: u32,
    /// NFT Information
    pub nfts: Vec<NFTInfo>,
    /// nonce
    pub nonce: u8,
    /// reward per token
    pub reward_per_token: u128,
    /// authorized funders
    /// [] because short size, fixed account size, and ease of use on 
    /// client due to auto generated account size property
    pub nft_provider: Pubkey,
}

#[account]
#[derive(Default)]
pub struct User {
    /// Pool the this user belongs to.
    pub pool: Pubkey,
    /// The owner of this account.
    pub owner: Pubkey,
    /// The amount of points redeemed.
    pub points_redeemed: u128,
    /// Points Balance.
    pub points_debt: u128,
    /// The amount staked.
    pub balance_staked: u128,
    /// last update time.
    pub last_update_time: u128,
    /// Signer nonce.
    pub nonce: u8,
}

#[error]
pub enum ErrorCode {
    #[msg("Insufficient funds to unstake.")]
    InsufficientFundUnstake,
    #[msg("Amount must be greater than zero.")]
    AmountMustBeGreaterThanZero,
    #[msg("Provided funder is already authorized to fund.")]
    FunderAlreadyAuthorized,
    #[msg("Maximum funders already authorized.")]
    MaxFunders,
    #[msg("Cannot deauthorize the primary pool authority.")]
    CannotDeauthorizePoolAuthority,
    #[msg("Authority not found for deauthorization.")]
    CannotDeauthorizeMissingAuthority,
    #[msg("NFT has been claimed")]
    NFTClaimed,
    #[msg("Insufficient Points")]
    InsufficientPoints,
    #[msg("NotMyStakingVault")]
    NotMyStakingVault,
}
