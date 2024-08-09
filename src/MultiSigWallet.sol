// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MultiSigWallet {
  event Deposit(address indexed sender, uint256 amount, uint256 balance);
  event SubmitTransaction(
    address indexed owner,
    uint256 indexed txIndex,
    address indexed to,
    uint256 value,
    bytes data
  );
  event ConfirmTransaction(address indexed owner, uint256 indexed txIndex);
  event ExecuteTransaction(address indexed owner, uint256 indexed txIndex);
  event RevokeConfirmation(address indexed owner, uint256 indexed txIndex);

  address[] public owners;
  mapping(address => bool) public isOwner;
  uint256 public numConfirmationsRequired;

  bytes32 public immutable DOMAIN_SEPARATOR;
  bytes32 public constant TRANSACTION_TYPEHASH =
    keccak256("Transaction(uint256 txIndex,address to,uint256 value,bytes data)");

  struct Transaction {
    address to;
    uint256 value;
    bytes data;
    bool executed;
    uint256 numConfirmations;
    mapping(address => bool) isConfirmed;
  }

  Transaction[] public transactions;

  modifier onlyOwner() {
    require(isOwner[msg.sender], "not owner");
    _;
  }

  modifier txExists(uint256 _txIndex) {
    require(_txIndex < transactions.length, "tx does not exist");
    _;
  }

  modifier notExecuted(uint256 _txIndex) {
    require(!transactions[_txIndex].executed, "tx already executed");
    _;
  }

  modifier notConfirmed(uint256 _txIndex) {
    require(!transactions[_txIndex].isConfirmed[msg.sender], "tx already confirmed");
    _;
  }

  constructor(address[] memory _owners, uint256 _numConfirmationsRequired) {
    require(_owners.length > 0, "owners required");
    require(
      _numConfirmationsRequired > 0 && _numConfirmationsRequired <= _owners.length,
      "invalid number of required confirmations"
    );

    for (uint256 i = 0; i < _owners.length; i++) {
      address owner = _owners[i];

      require(owner != address(0), "invalid owner");
      require(!isOwner[owner], "owner not unique");

      isOwner[owner] = true;
      owners.push(owner);
    }

    numConfirmationsRequired = _numConfirmationsRequired;
    uint256 chainId;
    assembly {
      chainId := chainid()
    }
    DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("MultiSigWallet")),
        keccak256(bytes("1")),
        chainId,
        address(this)
      )
    );
  }

  receive() external payable {
    emit Deposit(msg.sender, msg.value, address(this).balance);
  }

  function submitTransaction(address _to, uint256 _value, bytes memory _data) public onlyOwner {
    uint256 txIndex = transactions.length;

    transactions.push();
    Transaction storage transaction = transactions[txIndex];
    transaction.to = _to;
    transaction.value = _value;
    transaction.data = _data;
    transaction.executed = false;
    transaction.numConfirmations = 0;

    emit SubmitTransaction(msg.sender, txIndex, _to, _value, _data);
  }

  function confirmTransaction(
    uint256 _txIndex,
    bytes memory _signature
  ) public onlyOwner txExists(_txIndex) notExecuted(_txIndex) notConfirmed(_txIndex) {
    Transaction storage transaction = transactions[_txIndex];

    // verify signature
    bytes32 txHash = getTransactionHash(_txIndex, transaction.to, transaction.value, transaction.data);
    require(recoverSigner(txHash, _signature) == msg.sender, "invalid signature");

    transaction.isConfirmed[msg.sender] = true;
    transaction.numConfirmations += 1;

    emit ConfirmTransaction(msg.sender, _txIndex);
  }

  function executeTransaction(uint256 _txIndex) public txExists(_txIndex) notExecuted(_txIndex) {
    Transaction storage transaction = transactions[_txIndex];

    require(transaction.numConfirmations >= numConfirmationsRequired, "cannot execute tx");

    transaction.executed = true;

    (bool success, ) = transaction.to.call{value: transaction.value}(transaction.data);
    require(success, "tx failed");

    emit ExecuteTransaction(msg.sender, _txIndex);
  }

  function revokeConfirmation(uint256 _txIndex) public onlyOwner txExists(_txIndex) notExecuted(_txIndex) {
    Transaction storage transaction = transactions[_txIndex];

    require(transaction.isConfirmed[msg.sender], "tx not confirmed");

    transaction.isConfirmed[msg.sender] = false;
    transaction.numConfirmations -= 1;

    emit RevokeConfirmation(msg.sender, _txIndex);
  }

  function getOwners() public view returns (address[] memory) {
    return owners;
  }

  function getTransactionCount() public view returns (uint256) {
    return transactions.length;
  }

  function getTransaction(
    uint256 _txIndex
  ) public view returns (address to, uint256 value, bytes memory data, bool executed, uint256 numConfirmations) {
    Transaction storage transaction = transactions[_txIndex];

    return (transaction.to, transaction.value, transaction.data, transaction.executed, transaction.numConfirmations);
  }

  function getTransactionHash(
    uint256 _txIndex,
    address _to,
    uint256 _value,
    bytes memory _data
  ) public pure returns (bytes32) {
    return keccak256(abi.encode(TRANSACTION_TYPEHASH, _txIndex, _to, _value, keccak256(_data)));
  }

  function recoverSigner(bytes32 _hash, bytes memory _signature) internal view returns (address signer) {
    require(_signature.length == 65, "invalid signature length");

    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _hash));

    signer = ECDSA.recover(digest, _signature);
  }
}