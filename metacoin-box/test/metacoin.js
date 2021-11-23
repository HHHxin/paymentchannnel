const MetaCoin = artifacts.require("MetaCoin");
const {paymentType, hexToBytes, offchainSign, signRawMessage} = require('../src/utils')


contract('MetaCoin', (accounts) => {
  // it('should put 10000 MetaCoin in the first account', async () => {
  //   const metaCoinInstance = await MetaCoin.deployed();
  //   const balance = await metaCoinInstance.getBalance.call(accounts[0]);

  //   assert.equal(balance.valueOf(), 10000, "10000 wasn't in the first account");
  // });
  // it('should call a function that depends on a linked library', async () => {
  //   const metaCoinInstance = await MetaCoin.deployed();
  //   const metaCoinBalance = (await metaCoinInstance.getBalance.call(accounts[0])).toNumber();
  //   const metaCoinEthBalance = (await metaCoinInstance.getBalanceInEth.call(accounts[0])).toNumber();

  //   assert.equal(metaCoinEthBalance, 2 * metaCoinBalance, 'Library function returned unexpected function, linkage may be broken');
  // });
  // it('should send coin correctly', async () => {
  //   const metaCoinInstance = await MetaCoin.deployed();

  //   // Setup 2 accounts.
  //   const accountOne = accounts[0];
  //   const accountTwo = accounts[1];

  //   // Get initial balances of first and second account.
  //   const accountOneStartingBalance = (await metaCoinInstance.getBalance.call(accountOne)).toNumber();
  //   const accountTwoStartingBalance = (await metaCoinInstance.getBalance.call(accountTwo)).toNumber();

  //   // Make transaction from first account to second.
  //   const amount = 10;
  //   await metaCoinInstance.sendCoin(accountTwo, amount, { from: accountOne });

  //   // Get balances of first and second account after the transactions.
  //   const accountOneEndingBalance = (await metaCoinInstance.getBalance.call(accountOne)).toNumber();
  //   const accountTwoEndingBalance = (await metaCoinInstance.getBalance.call(accountTwo)).toNumber();


  //   assert.equal(accountOneEndingBalance, accountOneStartingBalance - amount, "Amount wasn't correctly taken from the sender");
  //   assert.equal(accountTwoEndingBalance, accountTwoStartingBalance + amount, "Amount wasn't correctly sent to the receiver");
  // });

  const candidatesLength = 13;
  const paticipatesLength = 10;

  const f = 4;
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
      await metaCoinInstance.participatesFund({from: accounts[i+13], value: C[i]});
    }
    for(let i = 0; i<paticipatesLength ; i++){
      assert.equal(await metaCoinInstance._balancesOfParticipate(await metaCoinInstance._participates(i)), C[i], '资金存入异常1');
    }
    
    assert.equal(await metaCoinInstance._allBalances(), 49, '资金存入异常2');
  });

  it('should call a function (validPayment)', async () => {
    const metaCoinInstance = await MetaCoin.deployed();
    
    let sig = signRawMessage([accounts[0], accounts[1], 2, 1], PrivateKeys[0]);
    let payment = {from:accounts[0], to:accounts[1], amounts:2, nonce:1};

    assert.equal(await metaCoinInstance.validPayment(payment, sig), true, '交易有效');
    assert.equal(await metaCoinInstance.validPayment(payment, sig), true, '交易有效1');
  });
});
