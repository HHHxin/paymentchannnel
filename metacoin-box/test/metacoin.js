const MetaCoin = artifacts.require("MetaCoin");
const MerkleMultiProof = artifacts.require('MerkleMultiProof');
const MerkleProof = artifacts.require('MerkleProof');
const { paymentType, 
  hexToBytes, 
  offchainSign, 
  signRawMessage, 
  signRawMessage2, 
  signRawMessage3, 
  signRawMessage4, 
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
    
    assert.equal(await metaCoinInstance._allCollateral(), 2800, '资金存入异常2');
  });


  it('should call a function (participateFund)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    for(let i = 0; i<paticipatesLength ; i++){
      await metaCoinInstance.participatesFund({from: accounts[i+candidatesLength], value: C[i]});
    }
    for(let i = 0; i<paticipatesLength ; i++){
      assert.equal(await metaCoinInstance._balancesOfParticipate(await metaCoinInstance._participates(i)), C[i], '资金存入异常1');
    }
    
    assert.equal(await metaCoinInstance._allBalances(), 2000, '资金存入异常2');
  });


  it('test select leader', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    // assert.equal(await metaCoinInstance._leaderIndex(), 0, '初始化选举异常');

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

  it('should call a function (validSnapShot)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();

    const leaves = [12,165, 1531, 68795, 465].map(v => keccak256(v));
    const tree = new MerkleTree(leaves, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const stateroot = tree.getHexRoot();
    
    let temppaymentArr = [];
    let temp;
    for(let i = 0; i<10; i++){
        temp = {from:accounts[i%paticipatesLength], to:accounts[(i+1)%paticipatesLength], amounts:1, nonce:i};
        temppaymentArr.push(JSON.stringify(temp));
    }
    const leaves1 = temppaymentArr.map(v => keccak256(v));
    const tree1 = new MerkleTree(leaves1, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const paymentroot = tree1.getHexRoot();

    let sig = signRawMessage4([stateroot, paymentroot, 100, 100], PrivateKeys[0]);
    let snapshot = {stateRoot:stateroot, paymentRoot:paymentroot, stateHeight: 100, totalFee:100};

    let flag = verifySignature4(accounts[0], [snapshot.stateRoot, snapshot.paymentRoot, snapshot.stateHeight, snapshot.totalFee], '0x'+sig.v.toString(16),sig.r,sig.s);
    
    console.log(`链下验证Snapshot：${flag}`);
    assert.equal(await metaCoinInstance.validSnapShot.call(snapshot, {account:accounts[0], sig:sig}), true, 'SnapShot无效');
  });

  it('should call a contract(MerkleProof)', async () => {
    const contract = await MerkleProof.new();
    const metaCoinInstance = await MetaCoin.deployed();
    const leaves = [12,165, 1531, 68795, 465].map(v => keccak256(v));
    const tree = new MerkleTree(leaves, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const root = tree.getHexRoot();

    let isGenRoot = await metaCoinInstance.isGeneratedRoot.call(leaves, root);
    let tx = await metaCoinInstance.isGeneratedRoot(leaves, root);
    let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    let gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    
    console.log(`genetated root的gas消耗：${gasUsed}`);
    console.log(`执行 generate root的价格: ${gasTestCost(gasUsed,gasPrice)}`);
    console.log(`生成的root哈希值：${isGenRoot.toString('hex')}`);
    console.log(`root哈希值：${root.toString('hex')}`);
    console.log(`生成的root是否正确：${isGenRoot}`)
    
  });

  // 模拟链下验证一批交易签名并生成状态数组
  it('should call a function (validBatchOfPayment)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    
    // let sig = signRawMessage([accounts[0], accounts[1], 2, 1], PrivateKeys[0]); 
    let paymentArr = new Array();
    // let tempArr = new Array();
    let sigArr = new Array();
    // 交易个数
    const arrLength = 10
    // 链下模拟一批交易
    for(let i = 0; i<arrLength; i++){
      // tempArr.push(accounts[candidatesLength+i%10]);
      // tempArr.push(accounts[candidatesLength+(i+1)%10]);
      // tempArr.push(1+i%2);
      // tempArr.push(i);
      paymentArr.push({from:accounts[candidatesLength+i%paticipatesLength], to:accounts[candidatesLength+(i+1)%paticipatesLength], amounts:1+i%2, nonce:i});
      sigArr.push(signRawMessage([accounts[candidatesLength+i%paticipatesLength], accounts[candidatesLength+(i+1)%paticipatesLength], 1+i%2, i], PrivateKeys[candidatesLength+i%paticipatesLength]));
    }

    // 链下验证所有交易
    let flag = true;
    for(let i = 0; i<arrLength; i++){
      let from = await metaCoinInstance._participatesBook(paymentArr[i].from);
      let to = await metaCoinInstance._participatesBook(paymentArr[i].to);
      if(from == false || to == false ) { flag = false;break; }

      let fromBalance = await metaCoinInstance._balancesOfParticipate(paymentArr[i].from);
      if(fromBalance < paymentArr[i].amounts) { flag = false;break; }

      if(!verifySignature([paymentArr[i].from, paymentArr[i].to, paymentArr[i].amounts, paymentArr[i].nonce], '0x'+sigArr[i].v.toString(16),sigArr[i].r,sigArr[i].s)){
        flag = false;break; 
      }
    }
    console.log(`链下验证交易：${flag}`);

    // let leaderSig = signRawMessage2(10,tempArr,PrivateKeys[0]);

    // 链上交易验证
    // assert.equal(await metaCoinInstance.validBatchOfPayment.call(paymentArr,sigArr), true, '验证这一批交易失败');

    // let tx = await metaCoinInstance.updatePayment(paymentArr,sigArr);

    // let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    // let gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    // console.log(`updatePayment消耗：${gasTestCost(gasUsed,gasPrice)}`);

  });

  it('leader生成状态数组与状态根,并上传验证', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    
    let totalFee = 0;
    let paymentArr = new Array();
    let temppaymentArr = new Array();
    let sigArr = new Array();
    let encodedMsg;
    let msgHex;
    let msgHashHex;
    // 交易个数
    const arrLength = 28
    // 链下模拟一批交易
    for(let i = 0; i<arrLength; i++){
      tempPayment = {from:accounts[candidatesLength+i%paticipatesLength], to:accounts[candidatesLength+(i+1)%paticipatesLength], amounts:100*(1+feeRate), nonce:i}
      paymentArr.push(tempPayment);      
      paymentSig = signRawMessage([accounts[candidatesLength+i%paticipatesLength], accounts[candidatesLength+(i+1)%paticipatesLength], 100*(1+feeRate), i], PrivateKeys[candidatesLength+i%paticipatesLength]);
      sigArr.push(paymentSig);
      tempPayment['sig'] = paymentSig;

      encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['address', 'address', 'uint256', 'uint256', 'uint8', 'bytes32', 'bytes32'],
        [accounts[candidatesLength+i%paticipatesLength], accounts[candidatesLength+(i+1)%paticipatesLength], 100*(1+feeRate), i, paymentSig.v, paymentSig.r, paymentSig.s]
      ).slice(2));
      msgHex = Buffer.from(encodedMsg, 'latin1').toString('hex');
      msgHashHex = web3.utils.keccak256('0x' + msgHex);
      temppaymentArr.push(msgHashHex);

      totalFee += 100 * feeRate;
    }

    // 链下验证所有交易
    let flag = true;
    for(let i = 0; i<arrLength; i++){
      let from = await metaCoinInstance._participatesBook(paymentArr[i].from);
      let to = await metaCoinInstance._participatesBook(paymentArr[i].to);
      if(from == false || to == false ) { flag = false;break; }

      let fromBalance = await metaCoinInstance._balancesOfParticipate(paymentArr[i].from);
      if(fromBalance < paymentArr[i].amounts) { flag = false;break; }

      if(!verifySignature([paymentArr[i].from, paymentArr[i].to, paymentArr[i].amounts, paymentArr[i].nonce], '0x'+sigArr[i].v.toString(16),sigArr[i].r,sigArr[i].s)){
        flag = false;break; 
      }
    }
    console.log(`链下验证交易：${flag}`);
    // 链上交易验证
    // assert.equal(await metaCoinInstance.validBatchOfPayment.call(paymentArr,sigArr), true, '验证这一批交易失败');

    // 交易签名验证成功，leader生成状态数组与状态根
    let balancesOfParticipateMap = new Map();
    let from,to,amount;
    let tempAmount;
    let tempAddress;
    // 生成所有参与者的状态Map
    // 上一轮参与者的状态Map State_i
    for(let i = 0; i < paticipatesLength; i++){
      tempAddress = accounts[candidatesLength+i];
      tempAmount = await metaCoinInstance._balancesOfParticipate(tempAddress);
      balancesOfParticipateMap.set(tempAddress,tempAmount);  
    }
    // 由本批次交易生成新的状态Map
    for(let i = 0; i < arrLength; i++){
      amount = paymentArr[i].amounts;
      from = balancesOfParticipateMap.get(paymentArr[i].from) - amount;
      to = balancesOfParticipateMap.get(paymentArr[i].to) + amount;

      balancesOfParticipateMap.set(paymentArr[i].from, from);
      balancesOfParticipateMap.set(paymentArr[i].to, to);
    }

    // 由状态Map生成state root
    let stateArr = [];
    for(let i = 0; i < paticipatesLength; i++){
      stateArr.push(balancesOfParticipateMap.get(accounts[candidatesLength+i]));
    }

    const leaves = stateArr.map(v => keccak256(v));
    const tree = new MerkleTree(leaves, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const root = tree.getHexRoot();
    const verified = await metaCoinInstance.isGeneratedRoot.call(leaves, root);
    assert.equal(verified, true, 'root验证无效');

    const leaves1 = temppaymentArr.map(v => keccak256(v));
    const tree1 = new MerkleTree(leaves1, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const paymentroot = tree1.getHexRoot();

    // 收集到2f+1个投票(root的签名,没有leader)
    let rootStateSigArr = new Array();
    let sigLength = 2*f + 1;
    let sig;
    let rootstate = {stateRoot:root, paymentRoot:paymentroot, stateHeight:arrLength, totalFee:totalFee};
    for(let i = 1; i <= sigLength; i++){    
      sig = signRawMessage4([root, paymentroot, arrLength, totalFee], PrivateKeys[i]);
      
      assert.equal(await metaCoinInstance.validSnapShot.call(rootstate, {account:accounts[i], sig:sig}), true, "签名无效");
      
      rootStateSigArr.push({account: accounts[i], sig: sig});
    }

    // 验证2f+1个投票（stateroot签名）
    assert.equal(await metaCoinInstance.validBatchOfSnapShot.call(rootstate, rootStateSigArr), true, "验证2f+1个snapshot签名失败");
    assert.equal(await metaCoinInstance.updateState.call(stateArr,leaves, rootstate, rootStateSigArr), true, '更新状态失败');
    let tx = await metaCoinInstance.updateState(stateArr,leaves, rootstate, rootStateSigArr);

    let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    console.log(`updateState消耗gasPrice：${gasPrice}`);
    let gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    let localGasCostWei = gasUsed.mul(gasPrice)
    let localGasCostETH = web3.utils.fromWei(localGasCostWei, 'ether')
    // let gasCost = gasUsed * gasPrice;
    console.log(`updateState消耗价格：${gasTestCost(gasUsed,gasPrice)}`);
    console.log(`updateState消耗gasUsed：${gasUsed}`);
    console.log(`updateState消耗ETH:${localGasCostETH}`);

    // for(let i = 0; i<candidatesLength; i++){
    //   tempFeeOfValidator = await metaCoinInstance._feeOfValidator(await metaCoinInstance._validators(i));
    //   console.log(`第${i}个验证者的Fee:${tempFeeOfValidator}`);
    // }

  });

  it('udpate后更换选举测试', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    console.log("select index: "+(await metaCoinInstance.selectLeader.call()));

    const tx = await metaCoinInstance.selectLeader();
    const gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    const gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    console.log(`update后选举消耗：${gasTestCost(gasUsed,gasPrice)}`);
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

    let tx = await metaCoinInstance.TxFraudProof(paymentroot, proof,rootSig,errorPaymentAndSig);
    let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    let gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    console.log(`TxFraudProof gas:${gasTestCost(gasUsed,gasPrice)}`);

  });


  it('writeRejectBook测试', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    for(let i = 0; i< 7; i++){
      let tx = await metaCoinInstance.writeRejectBook(i+1,{from: accounts[i+1]});
      let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
      let gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
      console.log(`writeRejectBook消耗：${gasTestCost(gasUsed,gasPrice)}`);
    }

    let totalFee = 0;
    let paymentArr = new Array();
    let temppaymentArr = new Array();
    let sigArr = new Array();
    let encodedMsg;
    let msgHex;
    let msgHashHex;
    // 交易个数
    const arrLength = 28
    // 链下模拟一批交易
    for(let i = 0; i<arrLength; i++){
      tempPayment = {from:accounts[candidatesLength+i%paticipatesLength], to:accounts[candidatesLength+(i+1)%paticipatesLength], amounts:100*(1+feeRate), nonce:i}
      paymentArr.push(tempPayment);      
      paymentSig = signRawMessage([accounts[candidatesLength+i%paticipatesLength], accounts[candidatesLength+(i+1)%paticipatesLength], 100*(1+feeRate), i], PrivateKeys[candidatesLength+i%paticipatesLength]);
      sigArr.push(paymentSig);
      tempPayment['sig'] = paymentSig;

      encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['address', 'address', 'uint256', 'uint256', 'uint8', 'bytes32', 'bytes32'],
        [accounts[candidatesLength+i%paticipatesLength], accounts[candidatesLength+(i+1)%paticipatesLength], 100*(1+feeRate), i, paymentSig.v, paymentSig.r, paymentSig.s]
      ).slice(2));
      msgHex = Buffer.from(encodedMsg, 'latin1').toString('hex');
      msgHashHex = web3.utils.keccak256('0x' + msgHex);
      temppaymentArr.push(msgHashHex);

      totalFee += 100 * feeRate;
    }

    let balancesOfParticipateMap = new Map();
    let from,to,amount;
    let tempAmount;
    let tempAddress;
    // 生成所有参与者的状态Map
    // 上一轮参与者的状态Map State_i
    for(let i = 0; i < paticipatesLength; i++){
      tempAddress = accounts[candidatesLength+i];
      tempAmount = await metaCoinInstance._balancesOfParticipate(tempAddress);
      balancesOfParticipateMap.set(tempAddress,tempAmount);  
    }
    // 由本批次交易生成新的状态Map
    for(let i = 0; i < arrLength; i++){
      amount = paymentArr[i].amounts;
      from = balancesOfParticipateMap.get(paymentArr[i].from) - amount;
      to = balancesOfParticipateMap.get(paymentArr[i].to) + amount;

      balancesOfParticipateMap.set(paymentArr[i].from, from);
      balancesOfParticipateMap.set(paymentArr[i].to, to);
    }

    // 由状态Map生成state root
    let stateArr = [];
    for(let i = 0; i < paticipatesLength; i++){
      stateArr.push(balancesOfParticipateMap.get(accounts[candidatesLength+i]));
    }

    const leaves = stateArr.map(v => keccak256(v));
    const tree = new MerkleTree(leaves, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const root = tree.getHexRoot();
    const verified = await metaCoinInstance.isGeneratedRoot.call(leaves, root);
    assert.equal(verified, true, 'root验证无效');

    const leaves1 = temppaymentArr.map(v => keccak256(v));
    const tree1 = new MerkleTree(leaves1, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const paymentroot = tree1.getHexRoot();

    // 收集到投accept票验证者的签名
    let rootStateSigArr = new Array();
    let sigLength = 12;
    let sig;
    let rootstate = {stateRoot:root, paymentRoot:paymentroot, stateHeight:arrLength, totalFee:totalFee};
    for(let i = 8; i <= sigLength; i++){    
      sig = signRawMessage4([root, paymentroot, arrLength, totalFee], PrivateKeys[i]);
      
      assert.equal(await metaCoinInstance.validSnapShot.call(rootstate, {account:accounts[i], sig:sig}), true, "签名无效");
      
      rootStateSigArr.push({account: accounts[i], sig: sig});
    }

    for(let i = 0; i<candidatesLength; i++){
      tempFeeOfValidator = await metaCoinInstance._collateralOfValidator(await metaCoinInstance._validators(i));
      console.log(`第${i}个验证者的Fee:${tempFeeOfValidator}`);
    }

    let tx = await metaCoinInstance.punishErrorVoter(rootstate, rootStateSigArr,{from: accounts[1]});
    let gasPrice = web3.utils.toBN(await web3.eth.getGasPrice());
    let gasUsed = web3.utils.toBN(tx.receipt.gasUsed);
    console.log(`punishErrorVoter消耗：${gasTestCost(gasUsed,gasPrice)}`);

    for(let i = 0; i<candidatesLength; i++){
      tempFeeOfValidator = await metaCoinInstance._collateralOfValidator(await metaCoinInstance._validators(i));
      console.log(`第${i}个验证者的Fee:${tempFeeOfValidator}`);
    }
  });

});
