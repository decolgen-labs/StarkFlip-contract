use starknet::ContractAddress;

#[starknet::interface]
trait IStarkFlip<TContractState> {
    fn get_owner(self: @TContractState) -> ContractAddress;
    fn get_contract_name(self: @TContractState) -> felt252;
    fn set_contract_name(ref self: TContractState, _name: felt252);
    fn set_partnership(ref self: TContractState, _target: ContractAddress, _active: bool);
    fn transfer_ownership(ref self: TContractState, _target: ContractAddress);
}

#[starknet::contract]
mod StarkFlip {
    use starknet::{ContractAddress, get_caller_address};
    use super::{IStarkFlip};

    #[storage]
    struct Storage {
        owner: ContractAddress,
        name: felt252,
        role_partnership: LegacyMap::<ContractAddress, bool>,
    }

    // ------------------ Constructor ------------------
    #[constructor]
    fn constructor(ref self: ContractState, _owner: ContractAddress) {
        self.owner.write(_owner);
        self.name.write('StarkFlip')
    }

    // --------------------- Event ---------------------
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TransferOwnership: TransferOwnership,
        SetPartnership: SetPartnership,
        SetContractName: SetContractName
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

    // --------------- External Accessors ---------------
    #[external(v0)]
    impl StarkFlipImpl of IStarkFlip<ContractState> {
        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn get_contract_name(self: @ContractState) -> felt252 {
            self.name.read()
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
