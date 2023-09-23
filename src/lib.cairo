use starknet::ContractAddress;

#[starknet::interface]
trait IERC20<TContractState> {
    fn name(self: @TContractState) -> felt252;

    fn symbol(self: @TContractState) -> felt252;

    fn decimals(self: @TContractState) -> u8;

    fn totalSupply(self: @TContractState) -> u256;

    fn balanceOf(self: @TContractState, account: ContractAddress) -> u256;

    fn allowance(self: @TContractState, owner: felt252, spender: felt252) -> u256;

    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;

    fn transferFrom(
        ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256
    ) -> bool;

    fn approve(ref self: TContractState, spender: felt252, amount: u256) -> bool;
}

#[starknet::interface]
trait IStarkFlip<TContractState> {
    fn get_owner(self: @TContractState) -> ContractAddress;
    fn get_contract_name(self: @TContractState) -> felt252;
    fn get_liquidity(self: @TContractState) -> u256;
    fn set_contract_name(ref self: TContractState, _name: felt252);
    fn set_partnership(ref self: TContractState, _target: ContractAddress, _active: bool);
    fn transfer_ownership(ref self: TContractState, _target: ContractAddress);
    fn add_liquidity(ref self: TContractState, _amount: felt252);
}

#[starknet::contract]
mod StarkFlip {
    use core::traits::Into;
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use super::{IStarkFlip, IERC20Dispatcher, IERC20DispatcherTrait};

    // ------------------- Constant -------------------

    #[storage]
    struct Storage {
        eth_address: ContractAddress,
        owner: ContractAddress,
        name: felt252,
        address: ContractAddress,
        role_partnership: LegacyMap::<ContractAddress, bool>,
        liquid: u256,
    }

    // ------------------ Constructor ------------------
    #[constructor]
    fn constructor(
        ref self: ContractState, _owner: ContractAddress, _eth_address: ContractAddress
    ) {
        self.owner.write(_owner);
        self.eth_address.write(_eth_address);
        self.name.write('StarkFlip')
    }

    // --------------------- Event ---------------------
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TransferOwnership: TransferOwnership,
        SetPartnership: SetPartnership,
        SetContractName: SetContractName,
        AddLiquidity: AddLiquidity
    }

    #[derive(Drop, starknet::Event)]
    struct TransferOwnership {
        #[key]
        prev_owner: ContractAddress,
        #[key]
        new_owner: ContractAddress
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

    // --------------- External Accessors ---------------
    #[external(v0)]
    impl StarkFlipImpl of IStarkFlip<ContractState> {
        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn get_contract_name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        fn get_liquidity(self: @ContractState) -> u256 {
            self.liquid.read()
        }

        fn set_contract_name(ref self: ContractState, _name: felt252) {
            Ownable::only_owner(@self);
            let prev_name = self.name.read();
            self.name.write(_name);
            self.emit(SetContractName { prev_name, new_name: _name });
        }

        fn set_partnership(ref self: ContractState, _target: ContractAddress, _active: bool) {
            Ownable::only_owner(@self);
            self.role_partnership.write(_target, _active);
            self.emit(SetPartnership { partnership: _target, active: _active });
        }

        fn transfer_ownership(ref self: ContractState, _target: ContractAddress) {
            Ownable::only_owner(@self);
            let prev_owner: ContractAddress = self.owner.read();
            self.owner.write(_target);
            self.emit(TransferOwnership { prev_owner, new_owner: _target });
        }

        fn add_liquidity(ref self: ContractState, _amount: felt252) {
            Ownable::only_owner_and_partnership(@self);
            let _from = get_caller_address();
            let this_contract = get_contract_address();
            let balance: u256 = _amount.into();
            let allowance = IERC20Dispatcher { contract_address: self.eth_address.read() }
                .allowance(_from.into(), this_contract.into());
            assert(allowance >= balance, 'Allowance does not enough');

            IERC20Dispatcher { contract_address: self.eth_address.read() }
                .transferFrom(_from, this_contract, balance);
            self.liquid.write(balance);

            self.emit(AddLiquidity { role_address: _from, amount: balance })
        }
    }

    // --------------- Internal Accessors ---------------
    #[generate_trait]
    impl Ownable of IOwnable {
        #[inline(always)]
        fn is_owner(self: @ContractState) -> bool {
            self.owner.read() == get_caller_address()
        }

        #[inline(always)]
        fn is_partnership(self: @ContractState) -> bool {
            self.role_partnership.read(get_caller_address())
        }

        fn only_owner(self: @ContractState) {
            assert(Ownable::is_owner(self), 'Only for owner');
        }

        fn only_partnership(self: @ContractState) {
            assert(Ownable::is_partnership(self), 'Only for partnership');
        }


        fn only_owner_and_partnership(self: @ContractState) {
            assert(
                Ownable::is_owner(self) || Ownable::is_partnership(self),
                'Only for owner and partnership'
            );
        }
    }
}
