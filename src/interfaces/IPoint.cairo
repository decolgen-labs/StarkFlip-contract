use starknet::ContractAddress;

#[starknet::interface]
trait IPoolPoint<TContractState> {
    fn rewardPoint(ref self: TContractState, amount: u256, timestamp: u64, proof: Array<felt252>);
    fn givePoint(ref self: TContractState, addressReceive: ContractAddress, amount: u256);
    fn setPermission(ref self: TContractState, address: ContractAddress, permission: bool);
    fn setSigner(ref self: TContractState, newSigner: ContractAddress);
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256);
    fn transferFrom(
        ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256
    );
    fn approve(ref self: TContractState, spender: ContractAddress, amount: u256);
    fn allowance(
        ref self: TContractState, owner: ContractAddress, spender: ContractAddress
    ) -> u256;
    fn getUserPoint(self: @TContractState, address: ContractAddress) -> u256;
    fn getOwner(self: @TContractState) -> ContractAddress;
    fn getSigner(self: @TContractState) -> ContractAddress;
}
