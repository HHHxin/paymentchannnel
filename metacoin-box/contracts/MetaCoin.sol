// // SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;
pragma experimental ABIEncoderV2;

import "./ConvertLib.sol";
import "./MerkleMultiProof.sol";
import "./MerkleProof.sol";

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
	
	uint256 public _leaderIndex;
	address payable public _leader;

	mapping(uint256 => bool) public _usedNonces;
	bytes32 public _currentRoot;

	modifier atPhase(Phase phase) {
        require(_phase == phase, 'Invalid phase');
        _;
    }

	constructor() {
		_phase = Phase.Open;

		_allCollateral = 0;
		_leaderIndex = 0;
		_allBalances = 0;
	}

	function candidateFund() public payable atPhase(Phase.Open) {
		_validators.push(payable(msg.sender));
		_validatorsBook[msg.sender] = true;
		_collateralOfValidator[msg.sender] += msg.value;
		_allCollateral += msg.value;
		if(_validators.length == 13){
			_leaderIndex = selectLeader();
			_leader = _validators[_leaderIndex];

			_phase = Phase.Join;
		}
	}

	function participatesFund() public payable atPhase(Phase.Join) {
		require(msg.value <= _allCollateral, 'Invalid Participate Fund');
		require(_allBalances < _allCollateral);

		_participates.push(payable(msg.sender));
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

	function validRoot(RootState calldata stateRoot, ECSignature calldata sig)
    public view returns(bool) {
		if( _validatorsBook[stateRoot.account] == false ) return false;

        bytes32 message = keccak256(abi.encode(stateRoot));
        if (checkPrefixedSig(stateRoot.account, message, sig)) {
            return true;
        }
        return false;
    }

	function validBatchOfRoot(RootState[] calldata stateRootArr, ECSignature[] calldata sigArr)
    public view returns(bool) {
		if(stateRootArr.length != 7 && sigArr.length != 7) return false;
		
		for(uint i = 0; i<stateRootArr.length; i++){
			if(validRoot(stateRootArr[i],sigArr[i]) == false) return false;
		}
		return true;
    }

	function updateState(uint[] calldata balancesArr, bytes32[] memory leaves, RootState[] calldata stateArr, ECSignature[] calldata sigArr) public returns(bool){
		//1 验证状态根
		if(!isGeneratedRoot(leaves, stateArr[0].root)) return false;
		// require(isGeneratedRoot(leaves, stateArr[0].root) == true);
		//2 验证对root的t个签名
		if(!validBatchOfRoot(stateArr, sigArr)) return false;
		// require(validBatchOfRoot(stateArr, sigArr) == true);
		
		// //3 更新状态
		_currentRoot = stateArr[0].root;
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

	function validBatchOfPayment(Payment[] calldata paymentArr, ECSignature[] calldata sigArr)
	public view atPhase(Phase.Exchange) returns(bool) {
		for(uint i = 0; i<paymentArr.length; i++){
			if(validPayment(paymentArr[i],sigArr[i]) == false){
				return false;
			}
		}
		return true;
	}

	// 把交易上传到链上进行验证，并转移状态
	function updatePayment(Payment[] calldata paymentArr, ECSignature[] calldata sigArr)
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

	function selectLeader() public returns(uint256 leaderIndex){
		if(_currentRoot == 0x0){
			return 0;
		}

		uint256 allCollateral= 0;
		uint256[] memory tempVector = new uint256[](_validators.length);
		for(uint i = 0; i < _validators.length; i++){
			allCollateral += _collateralOfValidator[_validators[i]];
			tempVector[i] = allCollateral;
		}

		uint256 random = uint256(keccak256(abi.encode(_currentRoot))) % allCollateral;
		for(uint i = 0; i < tempVector.length; i++){
			if(random <= tempVector[i]){
				return i;
			}
		}
	}

	function verify(bytes32 root, bytes32 leaf,bytes32[] memory proof) public returns (bool){
    	bytes32 computedHash = leaf;

    	for (uint256 i = 0; i < proof.length; i++) {
    		bytes32 proofElement = proof[i];
    		if (computedHash <= proofElement) {
    	    // Hash(current computed hash + current element of the proof)
    	    	computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
    		} else {
    	    // Hash(current element of the proof + current computed hash)
    	    	computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
    		}
    	}

    	// Check if the computed hash (root) is equal to the provided root
    	return computedHash == root;
  	}

	function isGeneratedRoot(bytes32[] memory tempHashes, bytes32 root) public returns(bool){
		bytes32 left;
		bytes32 right;
		uint L = tempHashes.length;
		uint j = 0;

		while(L > 1){
			j = 0;
			for(uint i = 0; i < L/2; i++){
				if(tempHashes[j] <= tempHashes[j+1]){
					left = tempHashes[j];
					right = tempHashes[j+1];
				}else{
					left = tempHashes[j+1];
					right = tempHashes[j];
				}
				tempHashes[i] = keccak256(abi.encodePacked(left, right));
				j += 2;
			}
			if((L/2 + L/2) != L){
				tempHashes[L/2] = tempHashes[L-1];
				L = L/2 + 1;
			}else{
				L = L/2;
			}
		}
		return tempHashes[0] == root;
	}
	

}
