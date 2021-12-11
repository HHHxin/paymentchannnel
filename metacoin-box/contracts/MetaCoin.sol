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

	struct SigOfAccount{
		address account;
		ECSignature sig;
	}

	struct Payment {
		address from;
		address to;
		uint256 amounts;
		uint256 nonce;
	}

	struct PaymentSig {
		address from;
		address to;
		uint256 amounts;
		uint256 nonce;
		// Sig
		uint8 v;
		bytes32 r;
		bytes32 s;
	}

	struct AccountBalances {
		address account;
		uint256 balances;
	}

	struct RootState {
		address account;
		bytes32 root;
	}

	struct SnapShot {
		bytes32 stateRoot;
		bytes32 paymentRoot;
		uint256 stateHeight;
		uint256 totalFee;
	}

	Phase public _phase;


	address payable[] public _validators;
	mapping(address => bool) public _validatorsBook;
	mapping(address => uint256) public _collateralOfValidator;
	mapping(address => uint256) public _feeOfValidator;
	uint256 public _allCollateral;

	address payable[] public _participates;
	mapping(address => bool) public _participatesBook;
	mapping(address => uint256) public _balancesOfParticipate;
	uint256 public _allBalances;
	
	uint256 public _leaderIndex;
	address payable public _leader;

	mapping(uint256 => bool) public _usedNonces;
	bytes32 public _currentRoot;
	bytes32 public _currentPaymentRoot;

	modifier atPhase(Phase phase) {
        require(_phase == phase, 'Invalid phase');
        _;
    }

	constructor() {
		_phase = Phase.Open;

		_allCollateral = 0;
		_allBalances = 0;
	}

	function candidateFund() public payable atPhase(Phase.Open) {
		_validators.push(payable(msg.sender));
		_validatorsBook[msg.sender] = true;
		_collateralOfValidator[msg.sender] += msg.value;
		_allCollateral += msg.value;
		if(_validators.length == 14){
			_phase = Phase.Join;
			_leaderIndex = 0;
			_leader = _validators[0];
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

	function validRoot(bytes32 paymentRoot, SigOfAccount memory sigOfaccount)
    public view returns(bool) {
		if( _validatorsBook[sigOfaccount.account] == false ) return false;

        bytes32 message = keccak256(abi.encode(paymentRoot));
        if (checkPrefixedSig(sigOfaccount.account, message, sigOfaccount.sig)) {
            return true;
        }
        return false;
    }

	// function validBatchOfRoot(RootState[] calldata stateRootArr, ECSignature[] calldata sigArr)
    // public view returns(bool) {
	// 	if(stateRootArr.length != 7 && sigArr.length != 7) return false;
		
	// 	for(uint i = 0; i<stateRootArr.length; i++){
	// 		if(validRoot(stateRootArr[i],sigArr[i]) == false) return false;
	// 	}
	// 	return true;
    // }

	function updateState(uint[] calldata balancesArr, bytes32[] memory leaves, SnapShot calldata snapshot, SigOfAccount[] calldata sigOfAccount) public returns(bool){
		//1 验证状态根
		// if(!isGeneratedRoot(leaves, snapshot.stateRoot)) return false;
		require(isGeneratedRoot(leaves, snapshot.stateRoot) == true);
		//2 验证对root的t个签名
		// if(!validBatchOfSnapShot(snapshot, sigOfAccount)) return false;
		bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encode(snapshot))));
		for(uint i = 0; i<sigOfAccount.length; i++){
        	// if(ecrecover(prefixedHash, sigOfAccount[i].sig.v, sigOfAccount[i].sig.r, sigOfAccount[i].sig.s) != sigOfAccount[i].account){
			// 	return false;
			// }
			require(ecrecover(prefixedHash, sigOfAccount[i].sig.v, sigOfAccount[i].sig.r, sigOfAccount[i].sig.s) == sigOfAccount[i].account);
		}
		
		//3 更新交易方状态
		_currentRoot = snapshot.stateRoot;
		_currentPaymentRoot = snapshot.paymentRoot;
		for(uint i = 0; i < balancesArr.length; i++){
			_balancesOfParticipate[_participates[i]] = balancesArr[i];
		}

		// 4 Leader与验证者分配交易fee
		_feeOfValidator[_leader] += snapshot.totalFee / 2;
		uint validatorFee = snapshot.totalFee  - snapshot.totalFee / 2;
		uint alvOfFee = validatorFee / sigOfAccount.length;
		for(uint i = 0; i < sigOfAccount.length; i++){
			_feeOfValidator[sigOfAccount[i].account] += alvOfFee;
		}
		return true;
	}

	function validSnapShot(SnapShot calldata snapshot, SigOfAccount calldata sigOfAccount) public pure returns(bool) {
		bytes32 message = keccak256(abi.encode(snapshot));
		if (checkPrefixedSig(sigOfAccount.account, message, sigOfAccount.sig)) {
            return true;
        }
        return false;
	}

	function validBatchOfSnapShot(SnapShot calldata snapshot, SigOfAccount[] calldata sigOfAccount)
	public pure returns(bool) {
		for(uint i = 0; i<sigOfAccount.length; i++){
			if(validSnapShot(snapshot, sigOfAccount[i]) == false){
				return false;
			}
		}
		return true;
	}

	function validPayment(Payment memory payment, ECSignature memory sig)
    public view returns(bool) {
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
	public view returns(bool) {
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

		uint256 allFee= 0;
		uint256[] memory tempVector = new uint256[](_validators.length);
		for(uint i = 0; i < _validators.length; i++){
			if(i != _leaderIndex){
				allFee += _feeOfValidator[_validators[i]];
				tempVector[i] = allFee;
			}else{
				tempVector[i] = allFee;
			}
		}

		uint256 random = uint256(keccak256(abi.encode(_currentRoot))) % allFee;
		for(uint i = 0; i < tempVector.length; i++){
			if(random <= tempVector[i]){
				return i;
			}
		}
	}

	function verify(bytes32 root, bytes32 leaf,bytes32[] calldata proof) public returns (bool){
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
	
	function TxFraudProof(bytes32 root, bytes32[] calldata proof, ECSignature calldata rootSig, PaymentSig calldata paymentSig) public returns(bool){
		// 1, 验证是否是leader签署的root
		if(!validRoot(root,SigOfAccount({account: _leader,sig: rootSig}))) return false;
		// 2. 验证交易签名是否错误
		if(validPayment(Payment({from:paymentSig.from, to:paymentSig.to, amounts: paymentSig.amounts, nonce: paymentSig.nonce}), 
						ECSignature({v:paymentSig.v,r:paymentSig.r,s:paymentSig.s}) )) return false;
		// 由交易生成leaf
		bytes32 prefixedHash = keccak256(abi.encode(paymentSig));
		bytes32 leaf = keccak256(abi.encode(prefixedHash));
		// 3. 验证错误交易是否存在merkle tree 中
		if(!verify(root, leaf, proof)) return false;

		return true;
	}

	function testHash123(PaymentSig memory paymentSig) pure public returns(bytes32) {
		bytes32 prefixedHash = keccak256(abi.encode(paymentSig));
		bytes32 leaf = keccak256(abi.encode(prefixedHash));
		// bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encode(payment))));
		return leaf;
	}

	// function setRejectBook(uint256 id)public returns(bool) {
	// 	uint temp = 1<<id;
	// 	rejectBook =rejectBook|temp;
	// 	if (countRejectBook() >=4)
	// 		return true;
	// 	else
	// 		return false;
	
	// }
	
	// function readRejectBook(uint256 id)public returns(uint256) {
	// 	return (rejectBook >>id)&1;
	// }

	// function countRejectBook()public returns(uint256) {
	// 	uint temmp = rejectBook;
	// 	uint count;
	// 	while (temmp !=0){
			
	// 		temmp &= temmp -1;
	// 		count++;
	// 	}
	// 	return count;
	// }

}
