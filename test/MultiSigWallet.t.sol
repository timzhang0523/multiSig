// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import  "../src/MultiSigWallet.sol";

contract TestERC20 is ERC20 {
  constructor() ERC20("TestToken", "TTK") {
    _mint(msg.sender, 1000 * 10 ** 18);
  }
}

contract MultiSigWalletTest is Test {
  MultiSigWallet multiSigWallet;
  TestERC20 testToken;
  address[] owners;
  uint256 owner0PK;
  uint256 owner1PK;
  uint256 owner2PK;
  uint256 numConfirmationsRequired;

  function setUp() public {
    owners = new address[](3);
    (owners[0], owner0PK) = makeAddrAndKey("owner0");
    (owners[1], owner1PK) = makeAddrAndKey("owner1");
    (owners[2], owner2PK) = makeAddrAndKey("owner2");
    numConfirmationsRequired = 2;

    multiSigWallet = new MultiSigWallet(owners, numConfirmationsRequired);
    vm.deal(address(multiSigWallet), 100 ether);

    testToken = new TestERC20();

    // Transfer some tokens to the multi-signature wallet
    testToken.transfer(address(multiSigWallet), 100 * 10 ** 18);
  }

  function testSubmitTransaction() public {
    vm.startPrank(owners[0]);
    multiSigWallet.submitTransaction(address(0xabc), 1 ether, "");
    (address to, uint256 value, bytes memory data, bool executed, uint256 numConfirmations) = multiSigWallet
      .getTransaction(0);
    assertEq(to, address(0xabc));
    assertEq(value, 1 ether);
    assertEq(data, "");
    assertEq(executed, false);
    assertEq(numConfirmations, 0);
    vm.stopPrank();
  }

  function testConfirmTransaction() public {
    vm.startPrank(owners[0]);
    multiSigWallet.submitTransaction(address(0xabc), 1 ether, "");
    bytes32 txHash = multiSigWallet.getTransactionHash(0, address(0xabc), 1 ether, "");
    bytes memory signature = signTransaction(txHash, owner0PK);
    multiSigWallet.confirmTransaction(0, signature);
    (, , , , uint256 numConfirmations) = multiSigWallet.getTransaction(0);
    assertEq(numConfirmations, 1);
    vm.stopPrank();
  }

  function testExecuteTransaction() public {
    vm.startPrank(owners[0]);
    multiSigWallet.submitTransaction(address(0xabc), 1 ether, "");
    bytes32 txHash = multiSigWallet.getTransactionHash(0, address(0xabc), 1 ether, "");
    bytes memory signature1 = signTransaction(txHash, owner0PK);
    bytes memory signature2 = signTransaction(txHash, owner1PK);
    multiSigWallet.confirmTransaction(0, signature1);
    vm.stopPrank();
    vm.startPrank(owners[1]);
    multiSigWallet.confirmTransaction(0, signature2);
    multiSigWallet.executeTransaction(0);
    (, , , bool executed, ) = multiSigWallet.getTransaction(0);
    assertEq(executed, true);
    assertEq(address(0xabc).balance, 1 ether);
    assertEq(address(multiSigWallet).balance, 99 ether);
    vm.stopPrank();
  }

  function testRevokeConfirmation() public {
    vm.startPrank(owners[0]);
    multiSigWallet.submitTransaction(address(0xabc), 1 ether, "");
    bytes32 txHash = multiSigWallet.getTransactionHash(0, address(0xabc), 1 ether, "");
    bytes memory signature1 = signTransaction(txHash, owner0PK);
    bytes memory signature2 = signTransaction(txHash, owner1PK);
    multiSigWallet.confirmTransaction(0, signature1);
    vm.stopPrank();
    vm.startPrank(owners[1]);
    multiSigWallet.confirmTransaction(0, signature2);
    vm.stopPrank();

    // Revoke confirmation
    vm.startPrank(owners[1]);
    multiSigWallet.revokeConfirmation(0);
    (, , , , uint256 numConfirmations) = multiSigWallet.getTransaction(0);
    assertEq(numConfirmations, 1); // Ensure the confirmation count decreased
    vm.stopPrank();

    // Attempt to execute transaction (should fail)
    vm.expectRevert("cannot execute tx");
    vm.startPrank(owners[0]);
    multiSigWallet.executeTransaction(0);
    vm.stopPrank();
  }

  function testExecuteERC20Transfer() public {
    vm.startPrank(owners[0]);
    bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", owners[2], 50 * 10 ** 18);
    multiSigWallet.submitTransaction(address(testToken), 0, data);
    bytes32 txHash = multiSigWallet.getTransactionHash(0, address(testToken), 0, data);
    bytes memory signature0 = signTransaction(txHash, owner0PK);
    bytes memory signature1 = signTransaction(txHash, owner1PK);
    multiSigWallet.confirmTransaction(0, signature0);
    vm.stopPrank();
    vm.startPrank(owners[1]);
    multiSigWallet.confirmTransaction(0, signature1);
    multiSigWallet.executeTransaction(0);
    vm.stopPrank();

    // Check balances
    assertEq(testToken.balanceOf(owners[2]), 50 * 10 ** 18);
    assertEq(testToken.balanceOf(address(multiSigWallet)), 50 * 10 ** 18);
  }

  function signTransaction(bytes32 txHash, uint256 privateKey) private view returns (bytes memory) {
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", multiSigWallet.DOMAIN_SEPARATOR(), txHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
    bytes memory sellListingSignature = abi.encodePacked(r, s, v);
    return sellListingSignature;
  }
}