use starknet::ContractAddress;

#[starknet::interface]
trait IStarkFlip<TContractState> {
    fn set_contract_name(ref self: TContractState, name: felt252);
    fn set_partnership(ref self: TContractState, target: ContractAddress, active: bool);
    fn set_pool_point(ref self: TContractState, new_pool_point: ContractAddress);
    fn add_liquidity(ref self: TContractState, amount: u256);
    fn withdraw_liquidity(ref self: TContractState, amount: u256);
    fn create_pool(
        ref self: TContractState,
        dealer: ContractAddress,
        min_stake_amount: u256,
        max_stake_amount: u256,
        fee_rate: u128
    );
    fn create_game(ref self: TContractState, pool_id: felt252, staked: u256, guess: u8);
    fn settle(ref self: TContractState, game_id: felt252, signature: Array<felt252>);
    fn cancel_game(ref self: TContractState, game_id: felt252);
    fn update_unit_point(ref self: TContractState, unit_point: u256);
}
