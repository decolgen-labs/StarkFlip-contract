// Copyright (C) 2024 Decolgen.

#[starknet::contract]
mod StarkFlip {
    use openzeppelin::access::ownable::interface::IOwnable;
    use starkflip::interfaces::{
        IStarkFlip::IStarkFlip, IPoint::{IPoolPointDispatcher, IPoolPointDispatcherTrait}
    };
    use pedersen::PedersenTrait;
    use poseidon::PoseidonTrait;
    use openzeppelin::account::interface::{AccountABIDispatcher, AccountABIDispatcherTrait};
    use openzeppelin::token::erc20::interface::{
        IERC20Dispatcher, IERC20CamelDispatcher, IERC20DispatcherTrait, IERC20CamelDispatcherTrait
    };
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::security::ReentrancyGuardComponent;
    use hash::{HashStateTrait, HashStateExTrait};
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address, get_tx_info,
        contract_address_const, get_block_timestamp, contract_address_to_felt252,
    };

    const STARKNET_DOMAIN_TYPE_HASH: felt252 =
        selector!("StarkNetDomain(name:felt,version:felt,chainId:felt)");
    const GAME_STRUCT_TYPE_HASH: felt252 =
        selector!("Settle(game_id:felt,guess:u8,seed:u128,timestamp:u64)");
    const U64: u128 = 0xffffffffffffffff_u128; // 2**64-1
    const WEI_UNIT: u256 = 0xDE0B6B3A7640000; // 1e18
    const FEE_PRECISION: u128 = 1_000_000;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: ReentrancyGuardComponent, storage: reentrancy, event: ReentrancyEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;

    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    impl ReentrancyInternalImpl = ReentrancyGuardComponent::InternalImpl<ContractState>;

    // ------------------- Constant -------------------
    #[storage]
    struct Storage {
        strk_address: ContractAddress,
        name: felt252,
        liquidity: u256,
        paused: bool,
        unit_point: u256,
        pool_point: ContractAddress,
        partnership: LegacyMap::<ContractAddress, bool>,
        shareholder: LegacyMap::<ContractAddress, u256>,
        pools: LegacyMap::<felt252, Pool>,
        games: LegacyMap::<felt252, Game>,
        treasury_receiver: ContractAddress,
        s0: u128,
        s1: u128,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        reentrancy: ReentrancyGuardComponent::Storage,
    }

    // ------------------ Constructor ------------------
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        strk_address: ContractAddress,
        treasury_receiver: ContractAddress,
        pool_point: ContractAddress,
        seed: u128,
        unit_point: u256,
    ) {
        self.strk_address.write(strk_address);
        self.ownable.initializer(owner);
        self.name.write('StarkFlip');
        self.liquidity.write(0);
        self.pool_point.write(pool_point);
        self.treasury_receiver.write(treasury_receiver);
        self.unit_point.write(unit_point);
        let s0 = splitmix(seed);
        let s1 = splitmix(s0);

        self.s0.write(s0);
        self.s1.write(s1);
    }

    // --------------------- Event ---------------------
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        SetPartnership: SetPartnership,
        SetContractName: SetContractName,
        AddLiquidity: AddLiquidity,
        WithdrawLiquidity: WithdrawLiquidity,
        CreatePool: CreatePool,
        CreateGame: CreateGame,
        SettleGame: SettleGame,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        ReentrancyEvent: ReentrancyGuardComponent::Event,
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
        id: felt252,
        dealer: ContractAddress,
        min_stake_amount: u256,
        max_stake_amount: u256,
        fee_rate: u128
    }

    #[derive(Drop, starknet::Event)]
    struct CreateGame {
        #[key]
        id: felt252,
        pool: felt252,
        player: ContractAddress,
        staked: u256,
        guess: u8,
        seed: u128,
        fee_rate: u128
    }

    #[derive(Drop, starknet::Event)]
    struct SettleGame {
        #[key]
        game_id: felt252,
        player: ContractAddress,
        is_won: bool,
        staked_amount: u256
    }

    // --------------------- Struct ---------------------

    #[derive(Drop, Copy, Serde, starknet::Store)]
    struct Pool {
        id: felt252,
        dealer: ContractAddress,
        min_stake_amount: u256,
        max_stake_amount: u256,
        fee_rate: u128
    }

    #[derive(Drop, Copy, Serde, starknet::Store)]
    struct Game {
        id: felt252,
        pool: felt252,
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
        game_id: felt252,
        guess: u8,
        seed: u128,
        timestamp: u64,
    }

    // --------------- External Accessors ---------------
    #[abi(embed_v0)]
    impl StarkFlipImpl of IStarkFlip<ContractState> {
        fn set_contract_name(ref self: ContractState, name: felt252) {
            self.ownable.assert_only_owner();
            let prev_name = self.name.read();
            self.name.write(name);
            self.emit(SetContractName { prev_name, new_name: name });
        }

        fn set_partnership(ref self: ContractState, target: ContractAddress, active: bool) {
            self.ownable.assert_only_owner();
            self.partnership.write(target, active);
            self.emit(SetPartnership { partnership: target, active: active });
        }

        fn set_pool_point(ref self: ContractState, new_pool_point: ContractAddress) {
            self.ownable.assert_only_owner();
            self.pool_point.write(new_pool_point)
        }

        fn add_liquidity(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            self._has_permission(caller);

            let this_contract = get_contract_address();
            let allowance = IERC20Dispatcher { contract_address: self.strk_address.read() }
                .allowance(caller.into(), this_contract.into());
            assert(allowance >= amount, 'Allowance does not enough');

            let new_stake_amount: u256 = amount + self.liquidity.read();
            IERC20CamelDispatcher { contract_address: self.strk_address.read() }
                .transferFrom(caller, this_contract, amount);
            self.liquidity.write(new_stake_amount);

            // update share amount
            let pre_shares = self.shareholder.read(caller);
            self.shareholder.write(caller, pre_shares + amount);

            self.emit(AddLiquidity { role_address: caller, amount })
        }

        fn withdraw_liquidity(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            self._has_permission(caller);

            let pre_shares: u256 = self.get_shares(caller);
            assert(amount <= pre_shares, 'STARKFLIP: Staked Not Enough');

            assert(self.liquidity.read() >= amount, 'STARKFLIP: Liquid Not Enough');

            // update data in storage
            let new_liquidity_amount: u256 = self.liquidity.read() - amount;
            self.liquidity.write(new_liquidity_amount);

            // update number of shares
            self.shareholder.write(caller, pre_shares - amount);

            IERC20CamelDispatcher { contract_address: self.strk_address.read() }
                .transfer(caller, amount);

            self.emit(WithdrawLiquidity { role_address: caller, amount })
        }

        fn create_pool(
            ref self: ContractState,
            dealer: ContractAddress,
            min_stake_amount: u256,
            max_stake_amount: u256,
            fee_rate: u128
        ) {
            self.ownable.assert_only_owner();
            assert(min_stake_amount < max_stake_amount, 'INVALID min statke amount');
            let tx_hash = get_tx_info().unbox().transaction_hash;

            let mut pool_data = PedersenTrait::new(0);
            pool_data = pool_data.update_with(dealer);
            pool_data = pool_data.update_with(min_stake_amount);
            pool_data = pool_data.update_with(max_stake_amount);
            pool_data = pool_data.update_with(fee_rate);
            pool_data = pool_data.update_with(tx_hash);

            let id = pool_data.finalize();
            let new_pool = Pool { id, dealer, min_stake_amount, max_stake_amount, fee_rate };

            self.pools.write(id, new_pool);

            self.emit(CreatePool { id, dealer, min_stake_amount, max_stake_amount, fee_rate })
        }


        fn create_game(ref self: ContractState, pool_id: felt252, staked: u256, guess: u8,) {
            self.reentrancy.start();
            self._when_not_paused();
            assert(
                staked == WEI_UNIT || staked == 2 * WEI_UNIT || staked == 5 * WEI_UNIT,
                'STARKFLIP: Invalid stake amount'
            );
            let player = get_caller_address();
            let this_contract = get_contract_address();
            let strk_dispatcher = IERC20Dispatcher { contract_address: self.strk_address.read() };
            let allowance = strk_dispatcher.allowance(player.into(), this_contract.into());
            assert(allowance >= staked, 'STARKFLIP: Allowance not enough');

            strk_dispatcher.transfer_from(player, this_contract, staked);

            let s0 = self.s0.read();
            let s1 = self.s1.read();

            let seed = (rotl(s0 * 5, 7) * 9) & U64;
            let s1 = (s1 ^ s0) & U64;
            self.s0.write((rotl(s0, 24) ^ s1 ^ (s1 * 65536)) & U64);
            self.s1.write((rotl(s1, 37) & U64));

            let (id, fee_rate) = self._new_game(player, pool_id, guess, staked, seed);
            self
                .emit(
                    CreateGame { id, pool: pool_id, player, guess, staked: staked, seed, fee_rate }
                );
            self.reentrancy.end();
        }

        fn settle(
            ref self: ContractState, game_id: felt252, timestamp: u64, signature: Array<felt252>
        ) {
            self.reentrancy.start();
            let mut game = self.games.read(game_id);
            assert(game.pool != 0, 'STARKFLIP: Invalid Game');

            let pool = self.pools.read(game.pool);
            let msgHash = self
                .get_message_hash(game_id, game.guess, game.seed, timestamp, pool.dealer);

            let sig_r = signature.at(0);
            let sig_s = signature.at(1);

            assert(
                self.is_valid_signature(pool.dealer, msgHash, signature) == 'VALID',
                'INVALID SIGNATURE'
            );

            game.pool = 0;
            self.games.write(game_id, game);

            let mut result = PoseidonTrait::new();
            result = result.update_with(*sig_r);
            result = result.update_with(*sig_s);
            result = result.update_with(game.guess);
            result = result.update_with(game.seed);
            result = result.update_with(timestamp);

            let hash = result.finalize();
            let hash_u256: u256 = hash.into();
            let player_won = (hash_u256 % 2).try_into().unwrap() == game.guess;

            let original_stake_amount = game.staked / 2;
            let fee_amount = self._compute_fee_amount(original_stake_amount, game.fee_rate);
            let reward = game.staked - fee_amount;
            let strk_dispatcher = IERC20CamelDispatcher {
                contract_address: self.strk_address.read()
            };
            strk_dispatcher.transfer(self.treasury_receiver.read(), fee_amount);

            if (player_won) {
                strk_dispatcher.transfer(game.player, reward);
            } else {
                self._update_liquidity(self.liquidity.read() + reward);
                self
                    .shareholder
                    .write(
                        self.owner(),
                        self.shareholder.read(self.owner()) + (original_stake_amount - fee_amount)
                    );
            }

            let pool_point = IPoolPointDispatcher { contract_address: self.pool_point() };
            let point = (original_stake_amount / WEI_UNIT) * self.unit_point();
            pool_point.givePoint(game.player, point.try_into().unwrap(),);

            self
                .emit(
                    SettleGame {
                        game_id: game.id,
                        player: game.player,
                        is_won: player_won,
                        staked_amount: original_stake_amount
                    }
                );
            self.reentrancy.end();
        }

        fn cancel_game(ref self: ContractState, game_id: felt252) {
            self.reentrancy.start();
            let mut game: Game = self.games.read(game_id);
            assert(game.pool != 0, 'STARKFLIP: INVALID GAME');
            let caller = get_caller_address();
            assert(game.player == caller || self.owner() == caller, 'Caller not allowed');

            game.pool = 0;
            self.games.write(game_id, game);

            let original_stake_amount = game.staked / 2;
            self.liquidity.write(self.liquidity.read() + original_stake_amount);
            IERC20CamelDispatcher { contract_address: self.strk_address.read() }
                .transfer(game.player, original_stake_amount);
            self.reentrancy.end();
        }

        fn update_unit_point(ref self: ContractState, unit_point: u256) {
            self.ownable.assert_only_owner();
            self.unit_point.write(unit_point);
        }
    }

    #[abi(per_item)]
    #[generate_trait]
    impl Pausable of IPausable {
        #[external(v0)]
        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        #[external(v0)]
        fn pause(ref self: ContractState) {
            self._when_not_paused();
            self.ownable.assert_only_owner();
            self.paused.write(true);
        }

        #[external(v0)]
        fn unpause(ref self: ContractState) {
            self._when_paused();
            self.ownable.assert_only_owner();
            self.paused.write(false);
        }
    }

    #[generate_trait]
    impl ValidateSignature of IValidateSignature {
        fn is_valid_signature(
            self: @ContractState, signer: ContractAddress, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            let account: AccountABIDispatcher = AccountABIDispatcher { contract_address: signer };
            account.is_valid_signature(hash, signature)
        }

        fn get_message_hash(
            self: @ContractState,
            game_id: felt252,
            guess: u8,
            seed: u128,
            timestamp: u64,
            signer: ContractAddress
        ) -> felt252 {
            let domain = StarknetDomain {
                name: 'StarkFlip', version: 1, chain_id: get_tx_info().unbox().chain_id
            };
            let mut state = PedersenTrait::new(0);
            state = state.update_with('StarkNet Message');
            state = state.update_with(domain.hash_struct());
            // This can be a field within the struct, it doesn't have to be get_caller_address().
            state = state.update_with(signer);
            let settle = Settle { game_id, guess, seed, timestamp };
            state = state.update_with(settle.hash_struct());
            // Hashing with the amount of elements being hashed 
            state = state.update_with(4);
            state.finalize()
        }
    }

    // --------------- View Accessors --------------
    #[abi(per_item)]
    #[generate_trait]
    impl ViewFunction of IViewFunction {
        #[external(v0)]
        fn get_contract_name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        #[external(v0)]
        fn get_liquidity(self: @ContractState) -> u256 {
            self.liquidity.read()
        }

        #[external(v0)]
        fn get_shares(self: @ContractState, shareholder_address: ContractAddress) -> u256 {
            self.shareholder.read(shareholder_address)
        }

        #[external(v0)]
        fn get_pool(self: @ContractState, id: felt252) -> Pool {
            self.pools.read(id)
        }

        #[external(v0)]
        fn get_game(self: @ContractState, id: felt252) -> Game {
            self.games.read(id)
        }

        #[external(v0)]
        fn pool_point(self: @ContractState) -> ContractAddress {
            self.pool_point.read()
        }

        #[external(v0)]
        fn unit_point(self: @ContractState) -> u256 {
            self.unit_point.read()
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
            state = state.update_with(*self.game_id);
            state = state.update_with(*self.guess);
            state = state.update_with(*self.seed);
            state = state.update_with(*self.timestamp);
            state = state.update_with(5);
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
    impl Internal of InternalTrait {
        fn _has_permission(self: @ContractState, target: ContractAddress) {
            assert(
                self.partnership.read(target) || target == self.owner(), 'STARKFLIP: Not Permission'
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

        fn _new_game(
            ref self: ContractState,
            player: ContractAddress,
            pool_id: felt252,
            guess: u8,
            staked: u256,
            seed: u128
        ) -> (felt252, u128) {
            assert(guess == 1 || guess == 0, 'STARKFLIP: Invalid Guess');

            let mut pool: Pool = self.pools.read(pool_id);
            assert(
                staked >= pool.min_stake_amount && staked <= pool.max_stake_amount,
                'STARKFLIP: Invalid Staked'
            );
            assert(self.liquidity.read() >= staked, 'STARKFLIP: Insufficient Liquid');

            let total_staked = staked * 2;
            self.liquidity.write(self.liquidity.read() - staked);

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

            let id = game_data.finalize();
            let new_game = Game {
                id, pool: pool_id, player, staked: total_staked, guess, seed, fee_rate
            };

            self.games.write(id, new_game);

            (id, fee_rate)
        }

        fn _compute_fee_amount(self: @ContractState, amount: u256, fee_rate: u128) -> u256 {
            (amount * fee_rate.into()) / FEE_PRECISION.into()
        }
    }
}
