use starknet::ContractAddress;

#[starknet::interface]
trait IPoolPoint<TContractState> {
    fn rewardPoint(ref self: TContractState, amount: u128, timestamp: u128, proof: Array<felt252>);
    fn givePoint(ref self: TContractState, addressReceive: ContractAddress, amount: u128);
    fn setPermission(ref self: TContractState, address: ContractAddress, permission: bool);
    fn setSigner(ref self: TContractState, newSigner: ContractAddress);
    fn getUserPoint(self: @TContractState, address: ContractAddress) -> u128;
    fn getOwner(self: @TContractState) -> ContractAddress;
    fn getSigner(self: @TContractState) -> ContractAddress;
}
