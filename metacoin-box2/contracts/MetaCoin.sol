// // SPDX-License-Identifier: MIT
pragma solidity >=0.8.10;
pragma experimental ABIEncoderV2;

contract MetaCoin {
	enum Phase {
		Open,Join,Update,Exchange,Close
	}

	enum ChallengesPhase {
		Init, LeaderRespond, ValidatorsRespond
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

	struct State {
		address account;
		uint256 balances;
	}

	struct StateProof{
		bytes32 stateRoot1;
		bytes32 stateRoot2;
		bytes32[] stateRootProof;
		bytes32[] proof1;
		bytes32[] proof2;
		Payment tx;
		State state1;
		State state2;
	}

	struct CheckPoint{
		uint256 leaderId;
		uint256 epoch;
		bytes32 stateRoot;
		bytes32 paymentRoot;
		bytes32 intervalStateRoot;
		uint256 totalFee;
	}

	Phase public _phase;

	address payable[] public _validators;
	mapping(address => bool) public _validatorsBook;
	mapping(address => uint256) public _collateralOfValidator;

	address payable[] public _participates;
	mapping(address => bool) public _participatesBook;
	uint256 public _allBalances;
	
	uint256 public _leaderIndex;
	address payable public _leader;

	mapping(uint256 => bool) public _usedNonces;

	uint256 _updateTime;
	ChallengesPhase _challengesPhase;
	
	CheckPoint _latesCheckPoint; // 最新的临时CheckPoint
	CheckPoint _lastCheckPoint; // 上一个已经确定的CheckPoint
	CheckPoint _challengesCheckPoint;
	uint256 public _voteBook;
	uint256 public _feeBook;
	uint256 public _alvFee;

	modifier atPhase(Phase phase) {
        require(_phase == phase, 'Invalid phase');
        _;
    }

	constructor() {
		_phase = Phase.Open;
	}

	function candidateFund() public payable atPhase(Phase.Open) {
		_validators.push(payable(msg.sender));
		_validatorsBook[msg.sender] = true;
		_collateralOfValidator[msg.sender] += msg.value;
		if(_validators.length == 14){
			_phase = Phase.Join;
			_leaderIndex = 0;
			_leader = _validators[0];
		}
	}

	function participatesFund() public payable atPhase(Phase.Join) {
		_participates.push(payable(msg.sender));
		_participatesBook[msg.sender] = true;
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

	function validCheckPoint(CheckPoint memory checkpoint, ECSignature memory sig, uint256 id) public view returns(bool){
		require(id<_validators.length);

		bytes32 message = keccak256(abi.encode(checkpoint));
        if (checkPrefixedSig(_validators[id], message, sig)) {
            return true;
        }
        return false;
	}

	function updateCheckPoint(CheckPoint calldata newCheckPoint, ECSignature[] calldata sig, uint256[] calldata idArr)public returns(bool){
		// require(msg.sender == _leader);
		require(sig.length == _validators.length);
		require(newCheckPoint.epoch > _latesCheckPoint.epoch);
		for(uint i = 0; i < sig.length; i++){
			require(validCheckPoint(newCheckPoint, sig[i], idArr[i]) == true,'checkpoint sig is not valid');
		}
		_lastCheckPoint = _latesCheckPoint;
		_latesCheckPoint = newCheckPoint;

		_collateralOfValidator[_leader] += newCheckPoint.totalFee / 2;
		_alvFee = (newCheckPoint.totalFee - newCheckPoint.totalFee / 2) / (_validators.length-1);
		_allBalances -= newCheckPoint.totalFee;

		_feeBook = 0;
		
		return true;
	}

	function allocateFee(uint256 id)public{
		require((_feeBook >> id)&1==0);

		uint temp = 1<<id;
		_feeBook = _feeBook|temp;
		_collateralOfValidator[_validators[id]] = _alvFee;
	}

	function initChallenge(CheckPoint calldata newCheckPoint) public{
		require(newCheckPoint.epoch > _latesCheckPoint.epoch);
		require(_challengesPhase == ChallengesPhase.Init);

		_challengesPhase = ChallengesPhase.LeaderRespond;
		_challengesCheckPoint = newCheckPoint;
		_updateTime = block.timestamp;
	}

	function timeoutChallenge() public{
		require(_challengesPhase != ChallengesPhase.Init);
		//leader超时
		if (_challengesPhase == ChallengesPhase.LeaderRespond){
    	    // leader misbehavior;
    	    //重新选举
			_leaderIndex = selectLeader();
			_leader = _validators[_leaderIndex];
			_updateTime = block.timestamp;
    	}
		else if(_challengesPhase == ChallengesPhase.ValidatorsRespond){
			//惩罚没有签名的验证者
			for(uint i = 0; i<_validators.length; i++){
				if(readVoteBook(i) == 0){
					_collateralOfValidator[msg.sender] += _collateralOfValidator[_validators[i]];
					_collateralOfValidator[_validators[i]] = 0;
				}
			}
    	    _voteBook = 0;

			_lastCheckPoint = _latesCheckPoint;
			_latesCheckPoint = _challengesCheckPoint;
    	}
		_challengesPhase = ChallengesPhase.Init;
	}

	function leaderPessimisticUpdate(ECSignature[] calldata sig, uint256[] calldata idArr)public {
		require(_challengesPhase == ChallengesPhase.LeaderRespond);
		// require(msg.sender == _leader);

		for(uint i = 0; i < sig.length; i++){
			// verify sig
			require(validCheckPoint(_challengesCheckPoint, sig[i], idArr[i]) == true,'checkpoint sig is not valid');
			// set book
			_voteBook = _voteBook|(1<<idArr[i]);
		}
		if(countVoteBook() == _validators.length){
			_voteBook = 0;
			_challengesPhase = ChallengesPhase.Init;

			_lastCheckPoint = _latesCheckPoint;
			_latesCheckPoint = _challengesCheckPoint;
		}
		else{
			_challengesPhase = ChallengesPhase.ValidatorsRespond;
			_updateTime = block.timestamp;
		}
		
	}

	function pessimisticVote(uint256 id) public returns(bool) {
		require(_challengesPhase == ChallengesPhase.ValidatorsRespond);
		require(countVoteBook() < _validators.length);
		require(_validatorsBook[msg.sender] == true);
		// require(_validators[id] == msg.sender);

		uint temp = 1<<id;
		_voteBook = _voteBook|temp;

		if(countVoteBook() == _validators.length){
			_challengesPhase = ChallengesPhase.Init;
			_voteBook = 0;

			_lastCheckPoint = _latesCheckPoint;
			_latesCheckPoint = _challengesCheckPoint;
			return true;
		}else{
			return false;
		}
		
	}

	function validPayment(Payment memory payment, ECSignature memory sig)
    public view returns(bool) {
		if(_usedNonces[payment.nonce] == true || 
			_participatesBook[payment.from] == false ||
		 	_participatesBook[payment.to] == false) {
			return false;
		}

        bytes32 message = keccak256(abi.encode(payment));
        if (checkPrefixedSig(payment.from, message, sig)) {
            return true;
        }
        return false;
    }

	function selectLeader() public returns(uint256 leaderIndex){

		uint256 allFee= 0;
		uint256 validatorsLength = _validators.length;
		uint256[] memory tempVector = new uint256[](validatorsLength);
		for(uint i = 0; i < validatorsLength; i++){
			if(i != _leaderIndex){
				allFee += _collateralOfValidator[_validators[i]];
				tempVector[i] = allFee;
			}else{
				tempVector[i] = allFee;
			}
		}

		uint256 random = uint256(keccak256(abi.encode(_latesCheckPoint, block.timestamp))) % allFee;
		for(uint i = 0; i < tempVector.length; i++){
			if(random <= tempVector[i]){
				return i;
			}
		}
	}

	function verify(bytes32 root, bytes32 leaf,bytes32[] calldata proof) public pure returns (bool){
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
	
	function StateFraudProof(bytes32 currentRoot, StateProof calldata stateProof)public returns(bool){
		bytes32 leaf = keccak256(abi.encode(stateProof.stateRoot1, stateProof.stateRoot2, stateProof.tx));
		if(!verify(currentRoot, leaf, stateProof.stateRootProof)) return false;
		if(stateProof.state1.account != stateProof.state2.account || stateProof.tx.from != stateProof.state1.account) return false;
		if(stateProof.state2.balances == (stateProof.state1.balances - stateProof.tx.amounts)) return false;
		bytes32 leaf1 = keccak256(abi.encode(stateProof.state1));
		bytes32 leaf2 = keccak256(abi.encode(stateProof.state2));
		if(!verify(stateProof.stateRoot1,leaf1,stateProof.proof1)) return false;
		if(!verify(stateProof.stateRoot2,leaf2,stateProof.proof2)) return false;

		return true;
	}

	function StateFraud(CheckPoint memory challengeCheckPoint, ECSignature[] memory sig, uint256[] memory idArr, StateProof calldata stateProof)public{
		require(challengeCheckPoint.epoch > _latesCheckPoint.epoch);

		uint256 allPunishCollateral = 0;

		for(uint i = 0; i < sig.length; i++){
			require(validCheckPoint(challengeCheckPoint, sig[i], idArr[i]));
			allPunishCollateral += _collateralOfValidator[_validators[idArr[i]]];
			_collateralOfValidator[_validators[idArr[i]]] = 0;
		}

		require(StateFraudProof(challengeCheckPoint.intervalStateRoot,stateProof));

		_lastCheckPoint = _latesCheckPoint;
		_latesCheckPoint = challengeCheckPoint;

		_collateralOfValidator[msg.sender] += allPunishCollateral;

		_leaderIndex = selectLeader();
		_leader = _validators[_leaderIndex];

	}

	function TxFraudProof(bytes32 root, bytes32[] calldata proof, ECSignature calldata rootSig, PaymentSig calldata paymentSig) public returns(bool){
		require(_validatorsBook[msg.sender] == true);

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

		// 4. 抵押物分给挑战者
		_collateralOfValidator[msg.sender] += _collateralOfValidator[_leader];
		_collateralOfValidator[_leader] = 0;

		// 5. 重新选举
		_leaderIndex = selectLeader();
		_leader = _validators[_leaderIndex];

		return true;
	}
	
	function readVoteBook(uint256 id)public view returns(uint256) {
		return (_voteBook >> id)&1;
	}

	function countVoteBook()public view returns(uint256) {
		uint temmp = _voteBook;
		uint count;
		while (temmp !=0){			
			temmp &= temmp -1;
			count++;
		}
		return count;
	}

	function ClosePC() public {
		require(msg.sender == _leader);
		
		_phase = Phase.Close;
	}

	function withdrawValidatorsCollateral(uint256 index) public payable atPhase(Phase.Close) {
		address payable tempAddress = _validators[index];
		require(msg.sender == tempAddress);
		require(_validatorsBook[tempAddress]);

		_validatorsBook[tempAddress] = false;
		tempAddress.transfer(_collateralOfValidator[tempAddress]);
	}

	function withdrawParticipateBalance(uint256 index, uint256 particiapteBalances, bytes32[] calldata proof) public payable atPhase(Phase.Close) {
		address payable tempAddress = _participates[index];
		require(msg.sender == tempAddress);
		require(_participatesBook[tempAddress]);
		// valid stateRoot leaf

		bytes32 leaf = keccak256(abi.encode(State({account:tempAddress, balances:particiapteBalances})));
		require(verify(_latesCheckPoint.stateRoot, leaf, proof));

		_participatesBook[tempAddress] = false;
		tempAddress.transfer(particiapteBalances);
	}
}
