const MetaCoin = artifacts.require("MetaCoin");
const MerkleMultiProof = artifacts.require('MerkleMultiProof')
const {paymentType, hexToBytes, offchainSign, signRawMessage, signRawMessage2, signRawMessage3} = require('../src/utils')
const { MerkleTree } = require('merkletreejs');
const keccak256 = require('keccak256');

contract('MetaCoin', (accounts) => {

  const candidatesLength = 13;
  const f=3;
  const paticipatesLength = 10;

  const C = [
    4,5,6,4,5,6,4,5,6,4,5,6,4
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
    
    assert.equal(await metaCoinInstance._allCollateral(), 64, '资金存入异常2');
  });


  it('should call a function (participateFund)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    for(let i = 0; i<paticipatesLength ; i++){
      await metaCoinInstance.participatesFund({from: accounts[i+candidatesLength], value: C[i]});
    }
    for(let i = 0; i<paticipatesLength ; i++){
      assert.equal(await metaCoinInstance._balancesOfParticipate(await metaCoinInstance._participates(i)), C[i], '资金存入异常1');
    }
    
    assert.equal(await metaCoinInstance._allBalances(), 49, '资金存入异常2');
  });

  it('should call a function (validPayment)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();;
    
    let sig = signRawMessage([accounts[candidatesLength], accounts[candidatesLength+1], 2, 1], PrivateKeys[candidatesLength]);
    let payment = {from:accounts[candidatesLength], to:accounts[candidatesLength+1], amounts:2, nonce:1};

    assert.equal(await metaCoinInstance.validPayment.call(payment, sig), true, '交易无效');
  });

  it('should call a contract(MerkleTree)', async () => {
    const contract = await MerkleMultiProof.new();
    const leaves = ['a', 'b', 'd', 'q', 'o', 'f'].map(keccak256).sort(Buffer.compare);
    const tree = new MerkleTree(leaves, keccak256, { sort: true });
    
    const root = tree.getRoot();
    const proofLeaves = ['a', 'b', 'd', 'q', 'o', 'f'].map(keccak256).sort(Buffer.compare);
    const proof = tree.getMultiProof(proofLeaves);
    const proofFlags = tree.getProofFlags(proofLeaves, proof);
    
    const verified = await contract.verifyMultiProof.call(root, proofLeaves, proof, proofFlags);

    assert.equal(verified, true, '验证无效');
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

    // let leaderSig = signRawMessage2(10,tempArr,PrivateKeys[0]);

    assert.equal(await metaCoinInstance.validBatchOfPayment.call(paymentArr,sigArr), true, '验证这一批交易失败');

    // const tx = await metaCoinInstance.updatePayment(paymentArr,sigArr);

    // const gasPrice = await web3.eth.getGasPrice()
    // const gasUsed = tx.receipt.gasUsed
    // const gasCost = gasUsed * gasPrice
    // assert.equal(gasCost, 100,'testerror');

  });

  it('leader生成状态数组与状态根,并上传验证', async () => {
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

    // let leaderSig = signRawMessage2(10,tempArr,PrivateKeys[0]);

    assert.equal(await metaCoinInstance.validBatchOfPayment.call(paymentArr,sigArr), true, '验证这一批交易失败');

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
    const contract = await MerkleMultiProof.new();
    let stateArr = [];
    for(let i = 0; i < paticipatesLength; i++){
      stateArr.push(balancesOfParticipateMap.get(accounts[candidatesLength+i]));
    }

    const leaves = [1, 2, 8, 4].map(keccak256).sort(Buffer.compare);
    const tree = new MerkleTree(leaves, keccak256, { sort: true });
    
    const root = tree.getRoot();
    const proofLeaves = [1, 2, 8, 4].map(keccak256).sort(Buffer.compare);
    const proof = tree.getMultiProof(proofLeaves);
    const proofFlags = tree.getProofFlags(proofLeaves, proof);
    
    const verified = await contract.verifyMultiProof.call(root, proofLeaves, proof, proofFlags);

    assert.equal(verified, true, 'root验证无效');




    // 收集到2f+1个投票(root的签名)
    let rootStateArr = new Array();
    let rootStateSigArr = new Array();
    let sigLength = 2*f + 1;
    let sig;
    let rootstate;
    for(let i = 0; i < sigLength; i++){
      rootstate = {account:accounts[i], root:root}
      sig = signRawMessage3([accounts[i], root], PrivateKeys[i]);
      
      assert.equal(await metaCoinInstance.validRoot.call(rootstate, sig), true, "签名无效");

      rootStateArr.push(rootstate);
      rootStateSigArr.push(sig);
    }

    // 验证2f+1个投票（stateroot签名）
    assert.equal(await metaCoinInstance.validBatchOfRoot.call(rootStateArr, rootStateSigArr), true, "验证2f+1个状态根签名失败");

    assert.equal(await metaCoinInstance.updateState.call(stateArr,rootStateArr, rootStateSigArr, root, proofLeaves, proof, proofFlags), true, '更新状态失败');
  });




});
