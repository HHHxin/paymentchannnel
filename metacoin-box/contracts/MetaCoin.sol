// // SPDX-License-Identifier: MIT
// pragma solidity >=0.4.25 <0.7.0;

// import "./ConvertLib.sol";

// // This is just a simple example of a coin-like contract.
// // It is not standards compatible and cannot be expected to talk to other
// // coin/token contracts. If you want to create a standards-compliant
// // token, see: https://github.com/ConsenSys/Tokens. Cheers!

// contract MetaCoin {
// 	mapping (address => uint) balances;

// 	event Transfer(address indexed _from, address indexed _to, uint256 _value);

// 	constructor() public {
// 		balances[tx.origin] = 10000;
// 	}

// 	function sendCoin(address receiver, uint amount) public returns(bool sufficient) {
// 		if (balances[msg.sender] < amount) return false;
// 		balances[msg.sender] -= amount;
// 		balances[receiver] += amount;
// 		emit Transfer(msg.sender, receiver, amount);
// 		return true;
// 	}

// 	function getBalanceInEth(address addr) public view returns(uint){
// 		return ConvertLib.convert(getBalance(addr),2);
// 	}

// 	function getBalance(address addr) public view returns(uint) {
// 		return balances[addr];
// 	}
// }

pragma solidity >=0.5.16;
pragma experimental ABIEncoderV2;

import "./ConvertLib.sol";

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

	Phase public _phase;

	address payable[] public _validators;
	mapping(address => uint256) public _collateralOfValidator;
	uint256 public _allCollateral;

	address payable[] public _participates;
	mapping(address => uint256) public _balancesOfParticipate;
	uint256 public _allBalances;
	
	uint16 public _leaderIndex;
	address payable public _leader;

	mapping(uint256 => bool) public _usedNonces;

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

		_allBalances += msg.value;
		if(_allBalances > _allCollateral){
			_allBalances -= msg.value;
			msg.sender.transfer(msg.value);
		} else{
			_participates.push(msg.sender);
			_balancesOfParticipate[msg.sender] += msg.value;

			if(_participates.length == 10){
				_phase = Phase.Exchange;
			}
		}
	
	}

    function checkPrefixedSig(address pk, bytes32 message, ECSignature memory sig)
    public pure returns(bool) {
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        return ecrecover(prefixedHash, sig.v, sig.r, sig.s) == pk;
    }

	function validPayment(Payment memory payment, ECSignature memory sig)
    public returns(bool) {
		if(_usedNonces[payment.nonce] == true){
			return false;
		}
        bytes32 message = keccak256(abi.encode(payment));
        if (checkPrefixedSig(payment.from, message, sig)) {
			_usedNonces[payment.nonce] = true;
            return true;
        }
        return false;
    }

}
