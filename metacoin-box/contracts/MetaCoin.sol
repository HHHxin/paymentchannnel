// // SPDX-License-Identifier: MIT
pragma solidity >=0.5.16;
pragma experimental ABIEncoderV2;

import "./ConvertLib.sol";
import "./MerkleMultiProof.sol";

contract MetaCoin {
	enum Phase {
		Open,Join,Update,Exchange,Close,Cancelled
	}

    struct ECSignature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

	struct Payment {
		address from;
		address to;
		uint256 amounts;
		uint256 nonce;
	}

	struct AccountBalances {
		address account;
		uint256 balances;
	}

	struct RootState {
		address account;
		bytes32 root;
	}

	Phase public _phase;

	address payable[] public _validators;
	mapping(address => bool) public _validatorsBook;
	mapping(address => uint256) public _collateralOfValidator;
	uint256 public _allCollateral;

	address payable[] public _participates;
	mapping(address => bool) public _participatesBook;
	mapping(address => uint256) public _balancesOfParticipate;
	uint256 public _allBalances;
	
	uint16 public _leaderIndex;
	address payable public _leader;

	mapping(uint256 => bool) public _usedNonces;
	bytes32 public _currentRoot;

	modifier atPhase(Phase phase) {
        require(_phase == phase, 'Invalid phase');
        _;
    }

	constructor() public{
		_phase = Phase.Open;

		_allCollateral = 0;
		_leaderIndex = 0;
		_allBalances = 0;
	}

	function candidateFund() public payable atPhase(Phase.Open) {
		_validators.push(msg.sender);
		_validatorsBook[msg.sender] = true;
		_collateralOfValidator[msg.sender] += msg.value;
		_allCollateral += msg.value;
		if(_validators.length == 13){
			//TODO1 select a leader
			_leaderIndex = 0;
			_leader = _validators[_leaderIndex];

			_phase = Phase.Join;
		}
	}

	function participatesFund() public payable atPhase(Phase.Join) {
		require(msg.value <= _allCollateral, 'Invalid Participate Fund');
		require(_allBalances < _allCollateral);

		_participates.push(msg.sender);
		_participatesBook[msg.sender] = true;
		_balancesOfParticipate[msg.sender] += msg.value;
		_allBalances += msg.value;
		if(_participates.length == 10){
			_phase = Phase.Exchange;
		}
	}

    function checkPrefixedSig(address pk, bytes32 message, ECSignature memory sig)
    public pure returns(bool) {
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        return ecrecover(prefixedHash, sig.v, sig.r, sig.s) == pk;
    }

	function validRoot(RootState memory stateRoot, ECSignature memory sig)
    public view returns(bool) {
		if( _validatorsBook[stateRoot.account] == false ) return false;

        bytes32 message = keccak256(abi.encode(stateRoot));
        if (checkPrefixedSig(stateRoot.account, message, sig)) {
            return true;
        }
        return false;
    }

	function validBatchOfRoot(RootState[] memory stateRootArr, ECSignature[] memory sigArr)
    public view returns(bool) {
		if(stateRootArr.length != 7 && sigArr.length != 7) return false;
		
		for(uint i = 0; i<stateRootArr.length; i++){
			if(validRoot(stateRootArr[i],sigArr[i]) == false) return false;
		}
		return true;
    }

	function updateState(uint[] memory balancesArr, RootState[] memory stateArr, ECSignature[] memory sigArr, bytes32 root , bytes32[] memory leafs, bytes32[] memory proofs, bool[] memory proofFlag) public returns(bool){
		//1 验证状态根
		if(!validMerkleRoot(root, leafs, proofs, proofFlag)) return false;
		//2 验证t个签名
		if(!validBatchOfRoot(stateArr, sigArr)) return false;
		
		//3 更新状态
		_currentRoot = root;
		for(uint i = 0; i < balancesArr.length; i++){
			_balancesOfParticipate[_participates[i]] = balancesArr[i];
		}

		return true;
	}

	function validPayment(Payment memory payment, ECSignature memory sig)
    public view atPhase(Phase.Exchange) returns(bool) {
		if(_usedNonces[payment.nonce] == true || 
			_participatesBook[payment.from] == false ||
		 	_participatesBook[payment.to] == false ||
		 	_balancesOfParticipate[payment.from] < payment.amounts) {
			return false;
		}

        bytes32 message = keccak256(abi.encode(payment));
        if (checkPrefixedSig(payment.from, message, sig)) {
            return true;
        }
        return false;
    }

	function validBatchOfPayment(Payment[] memory paymentArr, ECSignature[] memory sigArr)
	public view atPhase(Phase.Exchange) returns(bool) {
		for(uint i = 0; i<paymentArr.length; i++){
			if(validPayment(paymentArr[i],sigArr[i]) == false){
				return false;
			}
		}
		return true;
	}

	// 把交易上传到链上进行验证，并转移状态
	function updatePayment(Payment[] memory paymentArr, ECSignature[] memory sigArr)
	public atPhase(Phase.Exchange) returns(bool){
		for(uint i = 0; i<paymentArr.length; i++){
			if(validPayment(paymentArr[i],sigArr[i]) == false){
				return false;
			}
		}

		for(uint i = 0; i<paymentArr.length; i++){
			_balancesOfParticipate[paymentArr[i].from] -= paymentArr[i].amounts;
			_balancesOfParticipate[paymentArr[i].to] += paymentArr[i].amounts;
		}

		_phase = Phase.Update;
		return true;
	}

	function validMerkleRoot(bytes32 root, bytes32[] memory leafs, bytes32[] memory proofs, bool[] memory proofFlag)public returns(bool) {
		return new MerkleMultiProof().verifyMultiProof(root, leafs, proofs, proofFlag);
	}

	

}
