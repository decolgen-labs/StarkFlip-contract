use starknet::ContractAddress;
use integer::{u256_overflowing_add};
use openzeppelin::access::accesscontrol::AccessControl;

#[starknet::interface]
trait IStarkFlip<TContractState> {
    fn get_admin(self: @TContractState) -> ContractAddress;
    fn get_contract_name(self: @TContractState) -> felt252;
    fn get_pool(self: @TContractState) -> u256;
    fn get_shares(self: @TContractState, shareholder_address: ContractAddress) -> u256;
    fn set_contract_name(ref self: TContractState, name: felt252);
    fn set_partnership(ref self: TContractState, target: ContractAddress, active: bool);
    fn transfer_ownership(ref self: TContractState, target: ContractAddress);
    fn add_liquidity(ref self: TContractState, amount: u256);
    fn withdraw_liquidity(ref self: TContractState, amount: u256);
}

const ADMIN_ROLE: felt252 = selector!("ADMIN_ROLE");
const PARTNERSHIP_ROLE: felt252 = selector!("PARTNERSHIP_ROLE");

#[starknet::contract]
mod StarkFlip {
    use openzeppelin::token::erc20::interface::IERC20CamelDispatcherTrait;
    use core::traits::Into;
    use openzeppelin::token::erc20::interface::IERC20DispatcherTrait;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20CamelDispatcher};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use super::{IStarkFlip, AccessControl, ADMIN_ROLE, PARTNERSHIP_ROLE};

    // ------------------- Constant -------------------

    #[storage]
    struct Storage {
        eth_address: ContractAddress,
        name: felt252,
        admin: ContractAddress,
        pool: u256,
        shareholder: LegacyMap::<ContractAddress, u256>
    }

    // ------------------ Constructor ------------------
    #[constructor]
    fn constructor(
        ref self: ContractState, _owner: ContractAddress, _eth_address: ContractAddress
    ) {
        // AccessControl initialization
        let mut access_state = AccessControl::unsafe_new_contract_state();
        AccessControl::InternalImpl::initializer(ref access_state);
        AccessControl::InternalImpl::_grant_role(ref access_state, ADMIN_ROLE, _owner);

        self.eth_address.write(_eth_address);
        self.admin.write(_owner);
        self.name.write('StarkFlip');
        self.pool.write(0)
    }

    // --------------------- Event ---------------------
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TransferOwnership: TransferOwnership,
        SetPartnership: SetPartnership,
        SetContractName: SetContractName,
        AddLiquidity: AddLiquidity,
        WithdrawLiquidity: WithdrawLiquidity
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

    // --------------- External Accessors ---------------
    #[external(v0)]
    impl StarkFlipImpl of IStarkFlip<ContractState> {
        fn get_admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn get_contract_name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        fn get_pool(self: @ContractState) -> u256 {
            self.pool.read()
        }

        fn get_shares(self: @ContractState, shareholder_address: ContractAddress) -> u256 {
            self.shareholder.read(shareholder_address)
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

            let new_stake_amount: u256 = amount + self.pool.read();
            IERC20CamelDispatcher { contract_address: self.eth_address.read() }
                .transferFrom(caller, this_contract, amount);
            self.pool.write(new_stake_amount);

            // update share amount
            let pre_shares = self.shareholder.read(caller);
            self.shareholder.write(caller, pre_shares + amount);

            self.emit(AddLiquidity { role_address: caller, amount })
        }

        fn withdraw_liquidity(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            Private::_has_permission(@self, caller);

            let pre_shares: u256 = self.get_shares(caller);
            assert(amount <= pre_shares, 'Staked amount does not enough');

            // update data in storage
            let new_liquidity_amount: u256 = self.pool.read() - amount;
            self.pool.write(new_liquidity_amount);

            // update number of shares
            self.shareholder.write(caller, pre_shares - amount);

            IERC20CamelDispatcher { contract_address: self.eth_address.read() }
                .transfer(caller, amount);

            self.emit(WithdrawLiquidity { role_address: caller, amount })
        }
    }
    // --------------- Private Accessors ---------------
    #[generate_trait]
    impl Private of PrivateTrait {
        fn _has_permission(self: @ContractState, target: ContractAddress) {
            let unsafe_state = AccessControl::unsafe_new_contract_state();
            assert(
                AccessControl::AccessControlImpl::has_role(@unsafe_state, ADMIN_ROLE, target)
                    || AccessControl::AccessControlImpl::has_role(
                        @unsafe_state, PARTNERSHIP_ROLE, target
                    ),
                'Caller is missing role'
            );
        }
    }
}
