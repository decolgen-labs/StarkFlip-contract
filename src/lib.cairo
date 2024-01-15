use starknet::ContractAddress;
use openzeppelin::access::accesscontrol::AccessControl;
use array::ArrayTrait;

#[starknet::interface]
trait IStarkFlip<TContractState> {
    fn get_admin(self: @TContractState) -> ContractAddress;
    fn get_contract_name(self: @TContractState) -> felt252;
    fn get_liquidity(self: @TContractState) -> u256;
    fn get_shared_liquidity(self: @TContractState) -> u256;
    fn get_shares(self: @TContractState, shareholder_address: ContractAddress) -> u256;
    fn get_pool_staked(self: @TContractState, id: ContractAddress) -> u256;
    fn get_game_staked(self: @TContractState, id: ContractAddress) -> u256;
    fn get_treasury(self: @TContractState) -> u256;
    fn set_contract_name(ref self: TContractState, name: felt252);
    fn set_partnership(ref self: TContractState, target: ContractAddress, active: bool);
    fn transfer_ownership(ref self: TContractState, target: ContractAddress);
    fn add_liquidity(ref self: TContractState, amount: u256);
    fn withdraw_liquidity(ref self: TContractState, amount: u256);
    fn withdraw_treasury(ref self: TContractState, amount: u256);
    fn create_pool(
        ref self: TContractState,
        dealer: ContractAddress,
        min_stake_amount: u256,
        max_stake_amount: u256,
        staked_amount: u256,
        fee_rate: u128
    );
    fn topup_pool(ref self: TContractState, pool_id: ContractAddress, staked_amount: u256);
    fn create_game(ref self: TContractState, pool_id: ContractAddress, staked: u256, guess: u8);
    fn settle(ref self: TContractState, game_id: ContractAddress, signature: Array<felt252>);
    fn test_play(
        self: @TContractState,
        // game_id: ContractAddress,
        // pool_id: ContractAddress,
        // player: ContractAddress,
        // fee_rate: u128,
        signer: ContractAddress,
        guess: u8,
        // staked: u256,
        seed: u128,
        signature: Array<felt252>
    ) -> (felt252, felt252, felt252);
}

const ADMIN_ROLE: felt252 = selector!("ADMIN_ROLE");
const PARTNERSHIP_ROLE: felt252 = selector!("PARTNERSHIP_ROLE");
const STARKNET_DOMAIN_TYPE_HASH: felt252 =
    selector!("StarkNetDomain(name:felt,version:felt,chainId:felt)");
const U256_TYPE_HASH: felt252 = selector!("u256(low:felt,high:felt)");
const GAME_STRUCT_TYPE_HASH: felt252 = selector!("Settle(guess:u8,seed:u128)");
const U64: u128 = 0xffffffffffffffff_u128; // 2**64-1
const FEE_PRECISION: u128 = 1_000_000;


#[starknet::contract]
mod StarkFlip {
    use core::option::OptionTrait;
    use core::traits::TryInto;
    use openzeppelin::account::interface::AccountABIDispatcherTrait;
    use openzeppelin::account::AccountABIDispatcher;
    use box::BoxTrait;
    use result::ResultTrait;
    use array::ArrayTrait;
    use pedersen::PedersenTrait;
    use poseidon::PoseidonTrait;
    use openzeppelin::token::erc20::interface::IERC20CamelDispatcherTrait;
    use traits::Into;
    use openzeppelin::token::erc20::interface::{
        IERC20Dispatcher, IERC20CamelDispatcher, IERC20DispatcherTrait
    };
    use hash::{HashStateTrait, HashStateExTrait};
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address, get_tx_info,
        contract_address_const, get_block_timestamp
    };
    use super::{
        IStarkFlip, AccessControl, ADMIN_ROLE, PARTNERSHIP_ROLE, U64, STARKNET_DOMAIN_TYPE_HASH,
        GAME_STRUCT_TYPE_HASH, U256_TYPE_HASH, FEE_PRECISION
    };

    // ------------------- Constant -------------------
    #[storage]
    struct Storage {
        eth_address: ContractAddress,
        name: felt252,
        admin: ContractAddress,
        liquidity: u256,
        shared_liquidity: u256,
        paused: bool,
        shareholder: LegacyMap::<ContractAddress, u256>,
        pools: LegacyMap::<ContractAddress, Pool>,
        games: LegacyMap::<ContractAddress, Game>,
        treasury: u256,
        s0: u128,
        s1: u128
    }

    // ------------------ Constructor ------------------
    #[constructor]
    fn constructor(
        ref self: ContractState, _owner: ContractAddress, _eth_address: ContractAddress, seed: u128
    ) {
        // AccessControl initialization
        let mut access_state = AccessControl::unsafe_new_contract_state();
        AccessControl::InternalImpl::initializer(ref access_state);
        AccessControl::InternalImpl::_grant_role(ref access_state, ADMIN_ROLE, _owner);

        self.eth_address.write(_eth_address);
        self.admin.write(_owner);
        self.name.write('StarkFlip');
        self.liquidity.write(0);
        self.shared_liquidity.write(0);
        self.treasury.write(0);
        let s0 = splitmix(seed);
        let s1 = splitmix(s0);

        self.s0.write(s0);
        self.s1.write(s1);
    }

    // --------------------- Event ---------------------
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TransferOwnership: TransferOwnership,
        SetPartnership: SetPartnership,
        SetContractName: SetContractName,
        AddLiquidity: AddLiquidity,
        WithdrawLiquidity: WithdrawLiquidity,
        CreatePool: CreatePool,
        CreateGame: CreateGame,
        TopupPool: TopupPool,
        SettleGame: SettleGame
    }

    #[derive(Drop, starknet::Event)]
    struct TransferOwnership {
        #[key]
        prev_admin: ContractAddress,
        #[key]
        new_admin: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct SetPartnership {
        #[key]
        partnership: ContractAddress,
        active: bool
    }

    #[derive(Drop, starknet::Event)]
    struct SetContractName {
        #[key]
        prev_name: felt252,
        #[key]
        new_name: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct AddLiquidity {
        #[key]
        role_address: ContractAddress,
        amount: u256
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawLiquidity {
        #[key]
        role_address: ContractAddress,
        amount: u256
    }

    #[derive(Drop, starknet::Event)]
    struct CreatePool {
        #[key]
        id: ContractAddress,
        dealer: ContractAddress,
        min_stake_amount: u256,
        max_stake_amount: u256,
        staked_amount: u256,
        fee_rate: u128
    }

    #[derive(Drop, starknet::Event)]
    struct TopupPool {
        #[key]
        id: ContractAddress,
        staked_amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct CreateGame {
        #[key]
        id: ContractAddress,
        pool: ContractAddress,
        player: ContractAddress,
        staked: u256,
        guess: u8,
        seed: u128,
        fee_rate: u128
    }

    #[derive(Drop, starknet::Event)]
    struct SettleGame {
        #[key]
        game_id: ContractAddress,
        player: ContractAddress,
        is_won: bool,
        staked_amount: u256
    }

    // --------------------- Struct ---------------------

    #[derive(Drop, Copy, starknet::Store)]
    struct Pool {
        id: ContractAddress,
        dealer: ContractAddress,
        min_stake_amount: u256,
        max_stake_amount: u256,
        staked_amount: u256,
        fee_rate: u128
    }

    #[derive(Drop, Copy, Serde, starknet::Store)]
    struct Game {
        id: ContractAddress,
        pool: ContractAddress,
        player: ContractAddress,
        staked: u256,
        guess: u8,
        seed: u128,
        fee_rate: u128
    }

    #[derive(Drop, Copy, Serde, Hash)]
    struct StarknetDomain {
        name: felt252,
        version: felt252,
        chain_id: felt252,
    }

    #[derive(Drop, Copy, Serde, Hash)]
    struct Settle {
        guess: u8,
        seed: u128
    }

    // --------------- External Accessors ---------------
    #[external(v0)]
    impl StarkFlipImpl of IStarkFlip<ContractState> {
        fn get_admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn get_contract_name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        fn get_liquidity(self: @ContractState) -> u256 {
            self.liquidity.read()
        }

        fn get_treasury(self: @ContractState) -> u256 {
            self.treasury.read()
        }

        fn get_shared_liquidity(self: @ContractState) -> u256 {
            self.shared_liquidity.read()
        }

        fn get_shares(self: @ContractState, shareholder_address: ContractAddress) -> u256 {
            self.shareholder.read(shareholder_address)
        }

        fn get_pool_staked(self: @ContractState, id: ContractAddress) -> u256 {
            let pool = self.pools.read(id);
            pool.staked_amount
        }

        fn get_game_staked(self: @ContractState, id: ContractAddress) -> u256 {
            let game = self.games.read(id);
            game.staked
        }

        fn set_contract_name(ref self: ContractState, name: felt252) {
            let unsafe_state = AccessControl::unsafe_new_contract_state();
            AccessControl::InternalImpl::assert_only_role(@unsafe_state, ADMIN_ROLE);
            let prev_name = self.name.read();
            self.name.write(name);
            self.emit(SetContractName { prev_name, new_name: name });
        }

        fn set_partnership(ref self: ContractState, target: ContractAddress, active: bool) {
            let mut unsafe_state = AccessControl::unsafe_new_contract_state();
            AccessControl::InternalImpl::assert_only_role(@unsafe_state, ADMIN_ROLE);

            if active {
                AccessControl::InternalImpl::_grant_role(
                    ref unsafe_state, PARTNERSHIP_ROLE, target
                );
            } else {
                AccessControl::InternalImpl::_revoke_role(
                    ref unsafe_state, PARTNERSHIP_ROLE, target
                );
            }
            self.emit(SetPartnership { partnership: target, active: active });
        }

        fn transfer_ownership(ref self: ContractState, target: ContractAddress) {
            let mut unsafe_state = AccessControl::unsafe_new_contract_state();
            AccessControl::InternalImpl::assert_only_role(@unsafe_state, ADMIN_ROLE);

            let prev_admin: ContractAddress = self.admin.read();
            AccessControl::InternalImpl::_grant_role(ref unsafe_state, ADMIN_ROLE, target);
            AccessControl::InternalImpl::_revoke_role(ref unsafe_state, ADMIN_ROLE, prev_admin);
            self.admin.write(target);

            self.emit(TransferOwnership { prev_admin, new_admin: target });
        }

        fn add_liquidity(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            Private::_has_permission(@self, caller);

            let this_contract = get_contract_address();
            let allowance = IERC20Dispatcher { contract_address: self.eth_address.read() }
                .allowance(caller.into(), this_contract.into());
            assert(allowance >= amount, 'Allowance does not enough');

            let new_stake_amount: u256 = amount + self.liquidity.read();
            IERC20CamelDispatcher { contract_address: self.eth_address.read() }
                .transferFrom(caller, this_contract, amount);
            self.liquidity.write(new_stake_amount);

            // update share amount
            let pre_shares = self.shareholder.read(caller);
            self.shareholder.write(caller, pre_shares + amount);

            self.emit(AddLiquidity { role_address: caller, amount })
        }

        fn withdraw_liquidity(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            Private::_has_permission(@self, caller);

            let pre_shares: u256 = self.get_shares(caller);
            assert(amount <= pre_shares, 'STARKFLIP: STAKED NOT ENOUGH');

            // update data in storage
            let new_liquidity_amount: u256 = self.liquidity.read() - amount;
            self.liquidity.write(new_liquidity_amount);

            // update number of shares
            self.shareholder.write(caller, pre_shares - amount);

            IERC20CamelDispatcher { contract_address: self.eth_address.read() }
                .transfer(caller, amount);

            self.emit(WithdrawLiquidity { role_address: caller, amount })
        }

        fn withdraw_treasury(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            Private::_only_Admin(@self, caller);

            let pre_amount: u256 = self.treasury.read();
            assert(amount <= pre_amount, 'STARKFLIP: TREASURY NOT ENOUGH');

            // update data in storage
            let new_treasury_amount: u256 = pre_amount - amount;
            self.treasury.write(new_treasury_amount);

            IERC20CamelDispatcher { contract_address: self.eth_address.read() }
                .transfer(caller, amount);
        }

        fn create_pool(
            ref self: ContractState,
            dealer: ContractAddress,
            min_stake_amount: u256,
            max_stake_amount: u256,
            staked_amount: u256,
            fee_rate: u128
        ) {
            let caller = get_caller_address();
            Private::_only_Admin(@self, caller);

            assert(min_stake_amount < max_stake_amount, 'INVALID min statke amount');
            let shared_liquidity = self.shared_liquidity.read();
            let liquidity = self.liquidity.read();

            assert((liquidity - shared_liquidity) >= staked_amount, 'INSUFFICIENT LIQUIDITY');

            let tx_hash = get_tx_info().unbox().transaction_hash;

            let mut pool_data = PedersenTrait::new(0);
            pool_data = pool_data.update_with(dealer);
            pool_data = pool_data.update_with(min_stake_amount);
            pool_data = pool_data.update_with(max_stake_amount);
            pool_data = pool_data.update_with(staked_amount);
            pool_data = pool_data.update_with(fee_rate);
            pool_data = pool_data.update_with(tx_hash);

            let id: ContractAddress = pool_data.finalize().try_into().unwrap();
            let new_pool = Pool {
                id, dealer, min_stake_amount, max_stake_amount, staked_amount, fee_rate
            };

            self.pools.write(id, new_pool);
            self.shared_liquidity.write(self.shared_liquidity.read() + staked_amount);

            self
                .emit(
                    CreatePool {
                        id, dealer, min_stake_amount, max_stake_amount, staked_amount, fee_rate
                    }
                )
        }

        fn topup_pool(ref self: ContractState, pool_id: ContractAddress, staked_amount: u256) {
            let caller = get_caller_address();
            Private::_has_permission(@self, caller);

            let mut pool = self.pools.read(pool_id);
            assert(pool.dealer != contract_address_const::<0>(), 'STARKFLIP: INVALID POOL');

            let shared_liquidity = self.shared_liquidity.read();
            let liquidity = self.liquidity.read();
            assert((liquidity - shared_liquidity) >= staked_amount, 'INSUFFICIENT LIQUIDITY');

            pool.staked_amount = pool.staked_amount + staked_amount;
            self.shared_liquidity.write(self.shared_liquidity.read() + staked_amount);
            self.pools.write(pool_id, pool);

            self.emit(TopupPool { id: pool_id, staked_amount })
        }

        fn create_game(
            ref self: ContractState, pool_id: ContractAddress, staked: u256, guess: u8,
        ) {
            Private::_when_not_paused(@self);
            let player = get_caller_address();
            let this_contract = get_contract_address();
            let allowance = IERC20Dispatcher { contract_address: self.eth_address.read() }
                .allowance(player.into(), this_contract.into());
            assert(allowance >= staked, 'STARKFLIP: Allowance not enough');

            IERC20CamelDispatcher { contract_address: self.eth_address.read() }
                .transferFrom(player, this_contract, staked);

            let s0 = self.s0.read();
            let s1 = self.s1.read();

            let seed = (rotl(s0 * 5, 7) * 9) & U64;
            let s1 = (s1 ^ s0) & U64;
            self.s0.write((rotl(s0, 24) ^ s1 ^ (s1 * 65536)) & U64);
            self.s1.write((rotl(s1, 37) & U64));

            let (id, fee_rate, game) = Private::_new_game(
                ref self, player, pool_id, guess, staked, seed
            );
            self
                .emit(
                    CreateGame {
                        id, pool: pool_id, player, guess, staked: staked * 2, seed, fee_rate
                    }
                );
        }

        fn settle(ref self: ContractState, game_id: ContractAddress, signature: Array<felt252>) {
            Private::_when_not_paused(@self);
            let mut game = self.games.read(game_id);
            assert(game.pool != contract_address_const::<0>(), 'STARKFLIP: INVALID GAME');

            let pool = self.pools.read(game.pool);
            let msgHash = ValidateSignature::get_message_hash(
                @self, game.guess, game.seed, pool.dealer
            );

            let sig_r = signature.at(0);
            let sig_s = signature.at(1);

            assert(
                ValidateSignature::is_valid_signature(
                    @self, pool.dealer, msgHash, signature
                ) == 'VALID',
                'INVALID SIGNATURE'
            );

            game.pool = contract_address_const::<0>();
            self.games.write(game_id, game);

            let mut result = PoseidonTrait::new();
            result = result.update(*sig_r);
            result = result.update(*sig_s);

            let hash = result.finalize();
            let hash_u256: u256 = hash.into();
            let player_won = (hash_u256.low % 2).try_into().unwrap() == game.guess;

            let original_stake_amount = game.staked / 2;
            let fee_amount = Private::_compute_fee_amount(original_stake_amount, pool.fee_rate);
            let total_staked = game.staked - fee_amount;
            let reward = original_stake_amount - fee_amount;
            self.treasury.write(self.treasury.read() + fee_amount);

            if (player_won) {
                Private::_update_liquidity(ref self, (self.liquidity.read() - reward));
                Private::_update_pool_staked(ref self, pool.id, pool.staked_amount - reward);
                Private::_update_shared_liquidity(ref self, self.shared_liquidity.read() - reward);

                IERC20CamelDispatcher { contract_address: self.eth_address.read() }
                    .transfer(game.player, total_staked);
            } else {
                Private::_update_liquidity(ref self, (self.liquidity.read() + reward));
                Private::_update_pool_staked(ref self, pool.id, pool.staked_amount + reward);
                Private::_update_shared_liquidity(ref self, self.shared_liquidity.read() + reward);
            }

            self
                .emit(
                    SettleGame {
                        game_id: game.id,
                        player: game.player,
                        is_won: player_won,
                        staked_amount: original_stake_amount
                    }
                )
        }

        fn test_play(
            self: @ContractState,
            // game_id: ContractAddress,
            // pool_id: ContractAddress,
            // player: ContractAddress,
            // fee_rate: u128,
            signer: ContractAddress,
            guess: u8,
            // staked: u256,
            seed: u128,
            signature: Array<felt252>
        ) -> (felt252, felt252, felt252) {
            // let signer: ContractAddress = get_caller_address();
            // let game = Game { id: game_id, pool: pool_id, player, staked, guess, seed, fee_rate };
            let msgHash = ValidateSignature::get_message_hash(self, guess, seed, signer);

            let sig_r = signature.at(0);
            let sig_s = signature.at(1);

            assert(
                ValidateSignature::is_valid_signature(self, signer, msgHash, signature) == 'VALID',
                'INVALID SIGNATURE'
            );

            let mut result = PoseidonTrait::new();
            result = result.update(*sig_r);
            result = result.update(*sig_s);

            (*sig_r, *sig_s, result.finalize())
        // assert(
        //     ValidateSignature::is_valid_signature(@self, signer, msgHash, signature) == "VALID",
        //     'INVALID SIGNATURE'
        // );

        // let s0 = self.s0.read();
        // let s1 = self.s1.read();

        // let ranNum = (rotl(s0 * 5, 7) * 9) & U64;
        // let s1 = (s1 ^ s0) & U64;
        // self.s0.write((rotl(s0, 24) ^ s1 ^ (s1 * 65536)) & U64);
        // self.s1.write((rotl(s1, 37) & U64));

        // ranNum
        }
    }

    trait IPausable<TContractState> {
        fn is_paused(self: @TContractState) -> bool;
        fn pause(ref self: TContractState);
        fn unpause(ref self: TContractState);
    }

    #[external(v0)]
    impl Pausable of IPausable<ContractState> {
        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }
        fn pause(ref self: ContractState) {
            Private::_when_not_paused(@self);
            let caller = get_caller_address();
            let mut unsafe_state = AccessControl::unsafe_new_contract_state();
            AccessControl::InternalImpl::assert_only_role(@unsafe_state, ADMIN_ROLE);

            self.paused.write(true);
        }

        fn unpause(ref self: ContractState) {
            Private::_when_paused(@self);
            let caller = get_caller_address();
            let mut unsafe_state = AccessControl::unsafe_new_contract_state();
            AccessControl::InternalImpl::assert_only_role(@unsafe_state, ADMIN_ROLE);

            self.paused.write(false);
        }
    }

    trait IValidateSignature<T> {
        fn is_valid_signature(
            self: @ContractState, signer: ContractAddress, hash: felt252, signature: Array<felt252>
        ) -> felt252;
        fn get_message_hash(
            self: @ContractState, // game_id: ContractAddress,
            // pool_id: ContractAddress,
            // player: ContractAddress,
            // staked: u256,
            guess: u8,
            // seed: u128,
            // fee_rate: u128,
            seed: u128,
            signer: ContractAddress
        ) -> felt252;
    }

    #[external(v0)]
    impl ValidateSignature of IValidateSignature<Game> {
        fn is_valid_signature(
            self: @ContractState, signer: ContractAddress, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            let account: AccountABIDispatcher = AccountABIDispatcher { contract_address: signer };
            account.is_valid_signature(hash, signature)
        }

        fn get_message_hash(
            self: @ContractState, guess: u8, seed: u128, signer: ContractAddress
        ) -> felt252 {
            let domain = StarknetDomain {
                name: 'dappName', version: 1, chain_id: get_tx_info().unbox().chain_id
            };
            let mut state = PedersenTrait::new(0);
            state = state.update_with('StarkNet Message');
            state = state.update_with(domain.hash_struct());
            // This can be a field within the struct, it doesn't have to be get_caller_address().
            state = state.update_with(signer);
            let settle = Settle { guess, seed };
            state = state.update_with(settle.hash_struct());
            // Hashing with the amount of elements being hashed 
            state = state.update_with(4);
            state.finalize()
        }
    }

    // --------------- Private Accessors ---------------
    trait IStructHash<T> {
        fn hash_struct(self: @T) -> felt252;
    }
    impl StructHashStarknetDomain of IStructHash<StarknetDomain> {
        fn hash_struct(self: @StarknetDomain) -> felt252 {
            let mut state = PedersenTrait::new(0);
            state = state.update_with(STARKNET_DOMAIN_TYPE_HASH);
            state = state.update_with(*self);
            state = state.update_with(4);
            state.finalize()
        }
    }


    impl StructHashSettleStruct of IStructHash<Settle> {
        fn hash_struct(self: @Settle) -> felt252 {
            let mut state = PedersenTrait::new(0);
            state = state.update_with(GAME_STRUCT_TYPE_HASH);
            state = state.update_with(*self.guess);
            state = state.update_with(*self.seed);
            state = state.update_with(3);
            state.finalize()
        }
    }

    impl StructHashU256 of IStructHash<u256> {
        fn hash_struct(self: @u256) -> felt252 {
            let mut state = PedersenTrait::new(0);
            state = state.update_with(U256_TYPE_HASH);
            state = state.update_with(*self);
            state = state.update_with(3);
            state.finalize()
        }
    }

    fn rotl(x: u128, k: u128) -> u128 {
        assert(k <= 64, 'invalid k');
        // (x << k) | (x >> (64 - k))
        (x * pow2(k)) | rshift(x, 64 - k)
    }

    // https://xoshiro.di.unimi.it/splitmix64.c
    // uint64_t z = (x += 0x9e3779b97f4a7c15);
    // z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    // z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    // return z ^ (z >> 31);
    fn splitmix(x: u128) -> u128 {
        let z = (x + 0x9e3779b97f4a7c15) & U64;
        let z = ((z ^ rshift(z, 30)) * 0xbf58476d1ce4e5b9) & U64;
        let z = ((z ^ rshift(z, 27)) * 0x94d049bb133111eb) & U64;
        (z ^ rshift(z, 31)) & U64
    }

    #[inline(always)]
    fn rshift(v: u128, b: u128) -> u128 {
        v / pow2(b)
    }

    fn pow2(mut i: u128) -> u128 {
        let mut p = 1;
        loop {
            if i == 0 {
                break p;
            }
            p *= 2;
            i -= 1;
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn _has_permission(self: @ContractState, target: ContractAddress) {
            let unsafe_state = AccessControl::unsafe_new_contract_state();
            assert(
                AccessControl::AccessControlImpl::has_role(@unsafe_state, ADMIN_ROLE, target)
                    || AccessControl::AccessControlImpl::has_role(
                        @unsafe_state, PARTNERSHIP_ROLE, target
                    ),
                'STARKFLIP: MISSING ROLE'
            );
        }

        fn _only_Admin(self: @ContractState, target: ContractAddress) {
            let unsafe_state = AccessControl::unsafe_new_contract_state();
            assert(
                AccessControl::AccessControlImpl::has_role(@unsafe_state, ADMIN_ROLE, target),
                'STARKFLIP: ONLY ADMIN ROLE'
            );
        }

        fn _when_not_paused(self: @ContractState) {
            assert(!self.paused.read(), 'STARKFLIP: Contract paused');
        }

        fn _when_paused(self: @ContractState) {
            assert(self.paused.read(), 'STARKFLIP: Contract not paused');
        }

        fn _update_liquidity(ref self: ContractState, amount: u256) {
            self.liquidity.write(amount);
        }

        fn _update_pool_staked(ref self: ContractState, id: ContractAddress, amount: u256) {
            let mut pool = self.pools.read(id);
            pool.staked_amount = amount;
            self.pools.write(id, pool);
        }

        fn _update_shared_liquidity(ref self: ContractState, amount: u256) {
            self.shared_liquidity.write(amount);
        }

        fn _new_game(
            ref self: ContractState,
            player: ContractAddress,
            pool_id: ContractAddress,
            guess: u8,
            staked: u256,
            seed: u128
        ) -> (ContractAddress, u128, Game) {
            assert(guess == 1 || guess == 0, 'STARKFLIP: INVALID GUESS');

            let mut pool: Pool = self.pools.read(pool_id);
            assert(
                staked >= pool.min_stake_amount && staked <= pool.max_stake_amount,
                'STARKFLIP: INVALID STAKED'
            );
            assert(pool.staked_amount >= staked, 'STARKFLIP: INSUFFICIENT STAKED');

            let total_staked = staked * 2;
            pool.staked_amount = pool.staked_amount - staked;
            self.pools.write(pool_id, pool);

            let block_timestamp = get_block_timestamp();

            let fee_rate = pool.fee_rate;
            let mut game_data = PedersenTrait::new(0);
            game_data = game_data.update_with(player);
            game_data = game_data.update_with(pool_id);
            game_data = game_data.update_with(guess);
            game_data = game_data.update_with(staked);
            game_data = game_data.update_with(seed);
            game_data = game_data.update_with(fee_rate);
            game_data = game_data.update_with(block_timestamp);

            let id: ContractAddress = game_data.finalize().try_into().unwrap();
            let new_game = Game {
                id, pool: pool_id, player, staked: total_staked, guess, seed, fee_rate
            };

            self.games.write(id, new_game);

            (id, fee_rate, new_game)
        }

        fn _compute_fee_amount(amount: u256, fee_rate: u128) -> u256 {
            (amount * fee_rate.into()) / FEE_PRECISION.into()
        }
    }
}
