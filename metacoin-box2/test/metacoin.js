const MetaCoin = artifacts.require("MetaCoin");
// const MerkleProof = artifacts.require('MerkleProof');
const { paymentType, 
  hexToBytes, 
  offchainSign, 
  signRawMessage, 
  signRawMessage2, 
  signRawMessage3, 
  signRawMessage4,
  signRawMessage5,
  verifySignature, 
  verifySignature3, 
  verifySignature4, 
  gasTestCost
} = require('../src/utils')
const { MerkleTree } = require('merkletreejs');
const keccak256 = require('keccak256');

contract('MetaCoin', (accounts) => {

  const candidatesLength = 14;
  const f=3;
  const paticipatesLength = 10;
  const feeRate = 0.01;

  const C = [
    200,200,200,200,200,200,200,200,200,200,200,200,200,200
  ]

  const PrivateKeys = [
    '0x3dfa09990f68ad7311d4bbb0e3d3535c3dd1777f8cb7901c12aa8d701fcd243e',
    '0xd6f3c58ef5dbca94b08d68a2bb357933243750851fd5143072fec06b009de510',
    '0x5aff626344b3d3eeb76e165969261d9fb24b5f59a8f008887dfe1b7a6d521dc3',
    '0xddac1983606a922485ebdc505a52f0c963c411596f04d14ed29c3be637bc2e46',
    '0xe00240f53bc8bc426b1b2e90c29755c5b6bbb6f6cc9406a69d2f3a334e5fea51',
    '0xa20e4768fd128f4adce6a212ca3e0d96621b8f2ebad5a8699882132aef3cacfb',
    '0xa4b54b417f83f193ada34f72ebe22eb8b90c693dba75d0f19aba485b23b2ceac',
    '0xff7808c760eb4657f80dce6b932ee972a2efba0e52388ea8d27bd28f608f0387',
    '0x7f014ad49a56889f93526c72d880f575dde1ff840d75aac86063807d8a31e569',
    '0x0244ad712c6961cf4467abf3e606cbfa1c24c3cee4df1f65ae9851eab7ebc1eb',
    '0x66faf82d0f030d3bc9338a3472481f84482c1178eb400a6a68c30f0ad462aa6e',
    '0x9e87d43fb2928fe0688106af92169e76b7221cd346b13df70580729b371b37df',
    '0xa3ad74683d34a5a29d71bf449f9d1a13782d5a313cc7868c687c65b3d955d23c',
    '0xea2a29fad9d6ba7980208784f321f7d0b38251b1a82b23645e08b87c01dedc6f',
    '0x4c2ba57072d5abcfee77d3a218113967f3ad577bc71ee1f243f655da977cfef1',
    '0xb0d6d4a3bf03713e62c218001a49d994b8052d8dca528ec7354ab4e7df3bf330',
    '0x760056cc7f02096634af039e5c6dd81ed48cd774dbe57084e672710c5c78d8e4',
    '0x849123d283bf47cceccd468b0ee9a9de4524096ecc97e35ed6f1b9ee23b5ed16',
    '0x90d8706f230a07f875d7aa7cd81a985e7a17b65eabc9a92006edbdb2eec084b6',
    '0x767a8faebedce31ff330d38f15e3f4c79a9a19241d829f77ebc501754caa70b6',
    '0xbd5371f9655a6d7cad5a83821e586a85b6305457738b4321254b90d65becf60a',
    '0xd7dc8549c778d97ad2fe526cd667d5567db8e21fc3bfad072f5d28c1fdf927dd',
    '0x8fafc0b9de259dd20054b6954d94d6b5c692abc756084b56f44534632352c187',
    '0x6112f2be10cd3dc76651b6a69c37bc2480f5b08ebc0d697f190ec84588544d6a',
    '0x36b0954160b610a6a2f1e8f72040f86d8c98d4445986a4d3860100ab66251e14',
    '0x9e80677be1f0b27f64bfb26def4916249b306949ce70faec46c52ba3b0c6973c',
    '0xd44b7e25db861db80f0a263b2c027c41dde386932ccb814ab68f1b2e0539918e',
    '0x72c7c794439b3e3c132ed5851c9d10bb1f1a1ad50c922f338eb2c63ddf1caada',
    '0x5635135e2312150bf23244bc91e546dffc2bf9d827d35e78f37df9fecd8ddffe',
    '0x495643f756cdf2811c87016861a2d212fa60e9469a2eaa7e05a66b7edea56942',
  ];

  it('should call a function (candidateFund)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    for(let i = 0; i<candidatesLength; i++){
      await metaCoinInstance.candidateFund({from: accounts[i], value: C[i]});
    }
    for(let i = 0; i<candidatesLength; i++){
      assert.equal(await metaCoinInstance._collateralOfValidator(await metaCoinInstance._validators(i)), C[i], '资金存入异常1');
    }

    for(let i = 0; i < 14; i++){
      console.log('验证者'+i+":"+await metaCoinInstance._collateralOfValidator(accounts[i]));
    }

  });


  it('should call a function (participateFund)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    for(let i = 0; i<paticipatesLength ; i++){
      await metaCoinInstance.participatesFund({from: accounts[i+candidatesLength], value: C[i]});
    }
    
    assert.equal(await metaCoinInstance._allBalances(), 2000, '资金存入异常2');
  });


  it('test select leader', async () => {
    const metaCoinInstance = await MetaCoin.deployed();

    const tx = await metaCoinInstance.selectLeader();
    const gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    const gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    console.log(`选举消耗：${gasTestCost(gasUsed,gasPrice)}`);

  });

  it('should call a function (validPayment)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    
    let sig = signRawMessage([accounts[candidatesLength], accounts[candidatesLength+1], 2, 1], PrivateKeys[candidatesLength]);
    let payment = {from:accounts[candidatesLength], to:accounts[candidatesLength+1], amounts:2, nonce:1};
    let paymentSig = {from:accounts[candidatesLength], to:accounts[candidatesLength+1], amounts:2, nonce:1, v:sig.v, r:sig.r, s:sig.s};

    let flag = verifySignature([payment.from, payment.to, payment.amounts, payment.nonce], '0x'+sig.v.toString(16),sig.r,sig.s);
    assert.equal(flag, true, '验证交易失败');
    assert.equal(await metaCoinInstance.validPayment.call(payment, sig), true, '交易无效');
  });

  it('txFraudProof测试', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    
    let totalFee = 0;
    let temppaymentArr = new Array();
    let encodedMsg;
    let msgHex;
    let msgHashHex;
    // 交易个数
    const arrLength = 28
    // 链下模拟一批交易
    for(let i = 0; i<arrLength; i++){
      tempPayment = {from:accounts[candidatesLength+i%paticipatesLength], to:accounts[candidatesLength+(i+1)%paticipatesLength], amounts:100*(1+feeRate), nonce:i} 
      paymentSig = signRawMessage([tempPayment.from, tempPayment.to, tempPayment.amounts, tempPayment.nonce], PrivateKeys[candidatesLength+i%paticipatesLength]);

      encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['address', 'address', 'uint256', 'uint256', 'uint8', 'bytes32', 'bytes32'],
        [tempPayment.from, tempPayment.to, tempPayment.amounts, tempPayment.nonce, paymentSig.v, paymentSig.r, paymentSig.s]
      ).slice(2));
      msgHex = Buffer.from(encodedMsg, 'latin1').toString('hex');
      msgHashHex = web3.utils.keccak256('0x' + msgHex);
      temppaymentArr.push(msgHashHex);

      totalFee += 100 * feeRate;
    }

    // 生成错误交易
    errorPayment = {from:accounts[candidatesLength+arrLength%paticipatesLength], to:accounts[candidatesLength+(arrLength+1)%paticipatesLength], amounts:100*(1+feeRate), nonce:arrLength}
    errorPaymentSig = signRawMessage([errorPayment.from, errorPayment.to, errorPayment.amounts, errorPayment.nonce], PrivateKeys[candidatesLength+(arrLength-1)%paticipatesLength])
    errorPaymentAndSig = {from:errorPayment.from, to:errorPayment.to, amounts:errorPayment.amounts, nonce:errorPayment.nonce, v: errorPaymentSig.v, r: errorPaymentSig.r, s: errorPaymentSig.s}
    errorEncodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
      ['address', 'address', 'uint256', 'uint256', 'uint8', 'bytes32', 'bytes32'],
      [errorPayment.from, errorPayment.to, errorPayment.amounts, errorPayment.nonce, errorPaymentSig.v, errorPaymentSig.r, errorPaymentSig.s]
    ).slice(2));
    errorMsgHex = Buffer.from(errorEncodedMsg, 'latin1').toString('hex');
    errorMsgHashHex = web3.utils.keccak256('0x' + errorMsgHex);
    temppaymentArr.push(errorMsgHashHex);

    totalFee += 100 * feeRate;

    // 生成包含错误交易的paymentroot
    const leaves1 = temppaymentArr.map(v => keccak256(v));
    const tree1 = new MerkleTree(leaves1, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const paymentroot = tree1.getHexRoot();
    const leaf = keccak256(errorMsgHashHex).toString('hex');
    const proof = tree1.getHexProof(leaf);

    let leader = String(await metaCoinInstance._leader());
    let leaderIndex = Number(await metaCoinInstance._leaderIndex());
    console.log(`-----:${leader}`);
    console.log(`----index:${leaderIndex}`);
    // leader对包含错误交易的paymentRoot签名
    rootSig = signRawMessage3([paymentroot], PrivateKeys[leaderIndex]);
    // console.log("验证签名："+verifySignature3([leader, paymentroot],'0x'+rootSig.v.toString(16), rootSig.r, rootSig.s));

    let flag = await metaCoinInstance.TxFraudProof.call(paymentroot, proof,rootSig,errorPaymentAndSig);
    console.log(`txFraudProof验证结果：${flag}`);

    let tx = await metaCoinInstance.TxFraudProof(paymentroot, proof,rootSig,errorPaymentAndSig, {from: accounts[5]});
    let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    let gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    console.log(`TxFraudProof gas:${gasTestCost(gasUsed,gasPrice)}`);

    console.log("leaderIndex: "+await metaCoinInstance._leaderIndex());

  });

  it('stateFraudProof 测试', async() => {
    const metaCoinInstance = await MetaCoin.deployed();

    // stateFraudProof 测试
    let leaveslist = [];
    for(let i = 0; i < 50; i++){
      let encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['address', 'uint256'],
        [accounts[i], (i+1)*100]
      ).slice(2))
      leaveslist.push('0x' + Buffer.from(encodedMsg, 'latin1').toString('hex'))
    }
    const leaves1 = leaveslist.map(v => keccak256(v));
    const tree = new MerkleTree(leaves1, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const stateroot1 = tree.getHexRoot();
    const preleaf1 = hexToBytes(web3.eth.abi.encodeParameters(
      ['address', 'uint256'],
      [accounts[0], 100]
    ).slice(2));
    const leaf1 = keccak256('0x' + Buffer.from(preleaf1, 'latin1').toString('hex'));
    const proof1 = tree.getHexProof(leaf1);

    let leaveslist1 = [];
    for(let i = 0; i < 50; i++){
      let encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['address', 'uint256'],
        [accounts[i], (i+1)*200]
      ).slice(2));
      leaveslist1.push('0x' + Buffer.from(encodedMsg, 'latin1').toString('hex'));
    }
    const leaves2 = leaveslist1.map(v => keccak256(v));
    const tree2 = new MerkleTree(leaves2, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const stateroot2 = tree2.getHexRoot();
    const preleaf2 = hexToBytes(web3.eth.abi.encodeParameters(
      ['address', 'uint256'],
      [accounts[0], 200]
    ).slice(2))
    const leaf2 = keccak256('0x' + Buffer.from(preleaf2, 'latin1').toString('hex'));
    const proof2 = tree2.getHexProof(leaf2);

    let encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['bytes32', 'bytes32', 'address', 'address', 'uint256', 'uint256'],
        [stateroot1, stateroot2, accounts[0], accounts[1], 50, 1]
      ).slice(2));
    let msgHex = '0x' + Buffer.from(encodedMsg, 'latin1').toString('hex');
    // msgHashHex = web3.utils.keccak256('0x' + msgHex);
    let leaveslist3 = [];
    for(let i = 0; i < 100; i++){
      leaveslist3.push(encodedMsg);
    }
    leaveslist3.push(msgHex);
    let leaves = leaveslist3.map(v => keccak256(v));
    const tree3 = new MerkleTree(leaves, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const stateroot3 = tree3.getHexRoot();
    const proof3 = tree3.getHexProof(keccak256(msgHex));

    let tx = {from:accounts[0],to:accounts[1],amounts:50,nonce:1};
    let txEncodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
      ['address', 'address', 'uint256', 'uint256'],
      [tx.from, tx.to, tx.amounts, tx.nonce]
    ).slice(2));
    let txMsgHex = '0x' + Buffer.from(txEncodedMsg, 'latin1').toString('hex');
    let txLeaves = [txMsgHex].map(v => keccak256(v));
    let txTree = new MerkleTree(txLeaves, keccak256, { sortPairs: true, sortLeaves: false, sort: false }); 
    let paymentRoot = txTree.getHexRoot();

    let state1 = {account:accounts[0],balances:100};
    let state2 = {account:accounts[0],balances:200};
    let stateProof = {
      stateRoot1:stateroot1,
      stateRoot2:stateroot2,
      stateRootProof:proof3,
      proof1:proof1,
      proof2:proof2,
      tx:tx,
      state1:state1,
      state2:state2
    }

    let flag = await metaCoinInstance.StateFraudProof.call(stateroot3,stateProof);
    console.log(`stateFraudProof:${flag}`);
    assert.equal(await metaCoinInstance.StateFraudProof.call(stateroot3,stateProof), true, 'stateFraudProof验证失败')
  
    let tx1 = await metaCoinInstance.StateFraudProof(stateroot3,stateProof);
    let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    let gasUsed = web3.utils.toBN(tx1.receipt.gasUsed);
    console.log(`StateFraudProof gasCost:${gasTestCost(gasUsed,gasPrice)}`);
    console.log(`StateFraudProof gas:${gasUsed}`);
    // stateFraudProof 测试 ending.........

    // 测试validCheckPoint
    let checkpoint = {leaderId:0, epoch:1, stateRoot:stateroot2, paymentRoot:paymentRoot, intervalStateRoot:stateroot3, totalFee:10};
    let sig = signRawMessage5([checkpoint.leaderId, checkpoint.epoch, checkpoint.stateRoot, checkpoint.paymentRoot, checkpoint.intervalStateRoot, checkpoint.totalFee], PrivateKeys[0]);
    assert.equal(await metaCoinInstance.validCheckPoint.call(checkpoint, sig, 0), true, 'checkpoint签名无效');

    tempSigArr = []
    for(let i = 0; i < 14; i++){
      tempSigArr[i] = signRawMessage5([checkpoint.leaderId, checkpoint.epoch, checkpoint.stateRoot, checkpoint.paymentRoot, checkpoint.intervalStateRoot, checkpoint.totalFee], PrivateKeys[i]);
    }
    // update checkPoint
    assert.equal(await metaCoinInstance.updateCheckPoint.call(checkpoint, tempSigArr, [0,1,2,3,4,5,6,7,8,9,10,11,12,13], {from:accounts[await metaCoinInstance._leaderIndex()]}), true, 'updateCheckPoint成功');

    // test challenge
    let checkpoint1 = {leaderId:0, epoch:2, stateRoot:stateroot2, paymentRoot:paymentRoot, intervalStateRoot:stateroot3, totalFee:10};
    await metaCoinInstance.initChallenge(checkpoint1);
    

    tempSigArr1 = []
    for(let i = 0; i < 10; i++){
      tempSigArr1[i] = signRawMessage5([checkpoint1.leaderId, checkpoint1.epoch, checkpoint1.stateRoot, checkpoint1.paymentRoot, checkpoint1.intervalStateRoot, checkpoint1.totalFee], PrivateKeys[i]);
    }
    await metaCoinInstance.leaderPessimisticUpdate(tempSigArr1, [0,1,2,3,4,5,6,7,8,9]);

    console.log('countBook: '+await metaCoinInstance.countVoteBook.call());

    await metaCoinInstance.pessimisticVote(10);
    await metaCoinInstance.pessimisticVote(11);
    await metaCoinInstance.pessimisticVote(12);
    // await metaCoinInstance.timeoutChallenge({from:accounts[5]});
    assert.equal(await metaCoinInstance.pessimisticVote.call(13), true, '完全验证者投票');
    await metaCoinInstance.pessimisticVote(13);

    for(let i = 0; i < 14; i++){
      console.log('验证者'+i+":"+await metaCoinInstance._collateralOfValidator(accounts[i]));
    }

    // stateFraud 测试
    let challengeCheckpoint = {leaderId:0, epoch:3, stateRoot:stateroot2, paymentRoot:paymentRoot, intervalStateRoot:stateroot3, totalFee:10};
    challengeSigArr1 = []
    for(let i = 0; i < 4; i++){
      challengeSigArr1[i] = signRawMessage5([challengeCheckpoint.leaderId, challengeCheckpoint.epoch, challengeCheckpoint.stateRoot, challengeCheckpoint.paymentRoot, challengeCheckpoint.intervalStateRoot, challengeCheckpoint.totalFee], PrivateKeys[i]);
    }
    await metaCoinInstance.StateFraud(challengeCheckpoint, challengeSigArr1, [0,1,2,3], stateProof);

  });


});
