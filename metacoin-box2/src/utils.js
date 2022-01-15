const keccak256 = require('keccak256');
const { MerkleTree } = require('merkletreejs')
const fs = require("fs")
const Web3  = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:8545'));

const accounts = [
    '0xF7c2EB7cCcbE7cBAd45c3773AD211fbeb7b348eE',
    '0x992cf08451b84A8b5d34Cf258Ad1d661C64cCb90',
    '0x10EA1D51d3A9896de0ccDAc8dA18fe6e2d2d1919',
    '0x595C9d4B255a6f22616bf8460Cea77a2D0a1D96b',
    '0xF940686e1A4D97416B7F84Bf3bEdEAcc58AF38B2',
    '0x0cBb9d35e6fd64f8e802D7fC9127Fb822e656316',
    '0x5c08bb9060cB35812609aedd9c8c7C94E0eAA4E7',
    '0x6170F047bC976A2e42F1f13c7DAB2F48665e4761',
    '0xbf5D02D37dEe28cf61F5d5F8f64AC31fb09ACD0f',
    '0x1341a9F25654968A1A90f8B1842D5A9140062089',
    '0x4343aE5be4F87eD206386e9a267277FfeAaabe92',
    '0x14fE442B140232657BEC34739cAE2A825cbe29a6',
    '0xC0C9B920854CF6a869c2fd9f159C942Bd0cf222D',
    '0x30ddD402C514F949dF3550Da4Ed6bEd382863b5b',
    '0x3d415e747Dc473b23aa98FE0ba411F96bb6AD210',
    '0xFbd845b8f8Efcd4830975b722CA701BF2a67012f'
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
    '0xb0d6d4a3bf03713e62c218001a49d994b8052d8dca528ec7354ab4e7df3bf330'
]

const candidatesLength = 13;
const f=3;
const paticipatesLength = 10;

const txLength = [50, 100, 150, 200, 250, 300, 350, 400,450,500,550,600,650,700,750,800,850,900,950,1000];

// let sigLength = 2*f + 1; f = 3,5,7,9
const sigLimit = [7, 11, 15, 19];

const paymentType = ['address', 'address', 'uint256', 'uint256'];

function hexToBytes(hex) {
    let bytes = ''

    for (let c = 0; c < hex.length; c += 2) {
        bytes += String.fromCharCode(parseInt(hex.substr(c, 2), 16))
    }
    return bytes
}

function offchainSign(msg, privateKey) {
    const msgHex = Buffer.from(msg, 'latin1').toString('hex')
    const msgHashHex = web3.utils.keccak256('0x' + msgHex)
    const sig = web3.eth.accounts.sign(msgHashHex, privateKey)

    let { v, r, s } = sig
    v = parseInt(v, 16)

    return { v, r, s }
}

function signRawMessage(rawValue, privateKey) {
    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        paymentType, rawValue
    ).slice(2));

    return offchainSign(encodedMsg, privateKey)
}

function verifySignature(rawValue, v,r,s) {
    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        paymentType, rawValue
    ).slice(2));
    const msgHex = Buffer.from(encodedMsg, 'latin1').toString('hex');
    const msgHashHex = web3.utils.keccak256('0x' + msgHex);

    const tempAccount = web3.eth.accounts.recover(msgHashHex, v,r,s);
    return tempAccount == rawValue[0];
}

function signRawMessage2(length,rawValue, privateKey) {
    let valueType = [];
    for(let i = 0; i<length; i++){
        valueType.push('address');
        valueType.push('address');
        valueType.push('uint256');
        valueType.push('uint256');
    }

    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        valueType, rawValue
    ).slice(2))

    return offchainSign(encodedMsg, privateKey)
}

function signRawMessage3(rawValue, privateKey) {
    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['bytes32'], rawValue,
    ).slice(2));

    return offchainSign(encodedMsg, privateKey);
}

function verifySignature3(rawValue, v,r,s) {
    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['address','bytes32'], rawValue
    ).slice(2));
    const msgHex = Buffer.from(encodedMsg, 'latin1').toString('hex');
    const msgHashHex = web3.utils.keccak256('0x' + msgHex);

    const tempAccount = web3.eth.accounts.recover(msgHashHex, v,r,s);
    return tempAccount == rawValue[0];
}

function signRawMessage4(rawValue, privateKey) {
    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['bytes32', 'bytes32', 'uint256', 'uint256'], rawValue,
    ).slice(2));

    return offchainSign(encodedMsg, privateKey);
}

function verifySignature4(account,rawValue, v,r,s) {
    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['bytes32', 'bytes32', 'uint256', 'uint256'], rawValue
    ).slice(2));
    const msgHex = Buffer.from(encodedMsg, 'latin1').toString('hex');
    const msgHashHex = web3.utils.keccak256('0x' + msgHex);

    const tempAccount = web3.eth.accounts.recover(msgHashHex, v,r,s);
    return tempAccount == account;
}

function signRawMessage5(rawValue, privateKey) {
    const encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['uint256', 'uint256', 'bytes32', 'bytes32', 'bytes32', 'uint256'], rawValue,
    ).slice(2));

    return offchainSign(encodedMsg, privateKey);
}

function generateMerkleRootTest(){
    let leaveslist = [];
    for(let i = 0; i < 3; i++){
        leaveslist.push(hexToBytes(web3.eth.abi.encodeParameters(
            ['address', 'uint256'],
            [accounts[i], (i+1)*100]
          ).slice(2)))
    }
    const leaves1 = leaveslist.map(v => keccak256(v));
    const tree = new MerkleTree(leaves1, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const stateroot1 = tree.getHexRoot();
    const leaf1 = keccak256(hexToBytes(web3.eth.abi.encodeParameters(
        ['address', 'uint256'],
        [accounts[0], 100]
      ).slice(2)));
    console.log(`leaf1:${leaf1}`);
    const proof1 = tree.getHexProof(leaf1);

    let leaveslist1 = [];
    for(let i = 0; i < 3; i++){
        leaveslist1.push(hexToBytes(web3.eth.abi.encodeParameters(
            ['address', 'uint256'],
            [accounts[i], (i+1)*200]
        ).slice(2)))
    }
    const leaves2 = leaveslist1.map(v => keccak256(v));
    const tree2 = new MerkleTree(leaves2, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const stateroot2 = tree2.getHexRoot();
    const leaf2 = keccak256(hexToBytes(web3.eth.abi.encodeParameters(
        ['address', 'uint256'],
        [accounts[0], 200]
      ).slice(2))).toString('hex');
    const proof2 = tree2.getHexProof(leaf2);

    let encodedMsg = hexToBytes(web3.eth.abi.encodeParameters(
        ['bytes32', 'bytes32', 'address', 'address', 'uint256', 'uint256'],
        [stateroot1, stateroot2, accounts[1], accounts[0], 50, 1]
      ).slice(2));
    let msgHex = '0x' + Buffer.from(encodedMsg, 'latin1').toString('hex');
    // msgHashHex = web3.utils.keccak256('0x' + msgHex);
    let leaves = [msgHex].map(v => keccak256(v));
    console.log(leaves[0].toString('hex'));
    const tree3 = new MerkleTree(leaves, keccak256, { sortPairs: true, sortLeaves: false, sort: false });
    const stateroot3 = tree3.getHexRoot();
    const proof3 = tree3.getHexProof(msgHex);
}
// generateMerkleRootTest();

function testSnapshot() {
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

    let sig = signRawMessage4([accounts[0], stateroot, paymentroot, 100, 100], PrivateKeys[0]);
    let snapshot = {account:accounts[0], stateRoot:stateroot, paymentRoot:paymentroot, stateHeight: 100, totalFee: 100};

    let flag = verifySignature4([snapshot.account, snapshot.stateRoot, snapshot.paymentRoot, snapshot.stateHeight, snapshot.totalFee], '0x'+sig.v.toString(16),sig.r,sig.s);
    
    console.log("snapshot验证："+flag);
}

// let root,rootSig;

function doWork(txLength, sigLimitLength) {
    console.log(" ")
    console.log(`---------交易数：${txLength}---------`);
    console.log(`---------验证签名数：${sigLimitLength}---------`);
    let arrLength = txLength;
    // let sigLength = 2*f + 1; f = 3,5,7,9
    let sigLength = sigLimitLength;

    let balancesOfParticipateMap = new Map();

    //生成交易
    let paymentArr = [];
    let sigArr = []
    
    let rootStateArr = new Array();
    let rootStateSigArr = new Array();

    for(let i = 0; i<arrLength; i++){
        paymentArr.push({from:accounts[i%paticipatesLength], to:accounts[(i+1)%paticipatesLength], amounts:1, nonce:i});
        sigArr.push(signRawMessage([accounts[i%paticipatesLength], accounts[(i+1)%paticipatesLength], 1, i], PrivateKeys[i%paticipatesLength]));
    }

    let tempAmount;
    let tempAddress;
    // 生成状态数组
    for(let i = 0; i < paticipatesLength; i++){
      tempAddress = accounts[i];
      tempAmount = 10;
      balancesOfParticipateMap.set(tempAddress,tempAmount);
    }

    let start = performance.now();
    for(let i = 0; i<1; i++){
        testLeader(arrLength,paymentArr,sigArr,balancesOfParticipateMap);
    }
    let end = performance.now();
    let result = (end - start).toFixed(2)
    console.log(`打包交易验证生成root耗时:${result}ms`);
    // 3

    // 模拟生成2f+1个签名


    let rootstate;
    let sig;
    for(let i = 0; i < sigLength; i++){
        rootstate = {account:accounts[i%10], root:root};
        sig = signRawMessage3([accounts[i%10], root], PrivateKeys[i%10]);
        
        rootStateArr.push(rootstate);
        rootStateSigArr.push(sig);
    }

    let start1 = performance.now();
    for(let i = 0; i < 1; i++){
        testLeader2(sigLength,rootStateArr,rootStateSigArr);
    }
    let end1 = performance.now();
    let result1 = (end1 - start1).toFixed(2);
    console.log(`验证2f+1个签名耗时:${result1}ms`);

    tempData1[sigLength+''].push(result);
    tempData2[sigLength+''].push(result1);
    
}

// let tempData1 = new Object();
// let tempData2 = new Object();
// for(let i = 0; i<sigLimit.length; i++){
//     tempData1[sigLimit[i]+''] = [];
//     tempData2[sigLimit[i]+''] = [];
// }

// for(let i = 0; i<sigLimit.length; i++){
//     for(let j = 0; j<txLength.length; j++){
//         doWork(txLength[j],sigLimit[i]);
//     }
// }
// let data1 = JSON.stringify(tempData1);
// let data2 = JSON.stringify(tempData2);
// fs.writeFileSync('data1.json', data1);
// fs.writeFileSync('data2.json', data2);

function testLeader(arrLength,paymentArr,sigArr,balancesOfParticipateMap) {
    /**
     * 1. 验证交易签名
     * 2. 生成状态数组
     * 3. 生成 merkle root
     * 4. 为root 签名
     */
    let from,to,amount;
    // 验证交易签名，并更新本地状态
    for(let i = 0; i < arrLength; i++){
        if(!verifySignature([paymentArr[i].from, paymentArr[i].to, paymentArr[i].amounts, paymentArr[i].nonce], '0x'+sigArr[i].v.toString(16),sigArr[i].r,sigArr[i].s)){
            continue;
        }

        amount = paymentArr[i].amounts;
        from = balancesOfParticipateMap.get(paymentArr[i].from) - amount;
        if(from<0) continue;
        to = balancesOfParticipateMap.get(paymentArr[i].to) + amount;

        balancesOfParticipateMap.set(paymentArr[i].from, from);
        balancesOfParticipateMap.set(paymentArr[i].to, to);
    }

    // 生成状态数组
    let stateArr = [];
    for(let i = 0; i < paticipatesLength; i++){
      stateArr.push(balancesOfParticipateMap.get(accounts[i]));
    }

    const leaves = stateArr.map(keccak256).sort(Buffer.compare);
    const tree = new MerkleTree(leaves, keccak256, { sort: true });
    
    root = tree.getRoot();

    rootSig = signRawMessage3([accounts[0], root], PrivateKeys[0]);

    verifySignature3([accounts[0], root], '0x'+rootSig.v.toString(16),rootSig.r,rootSig.s);
    // 发送 rootSig，批交易，状态数组
    // ...
}

function testLeader2(sigLength,rootStateArr,rootStateSigArr) {
    // 验证2f+1个root签名
    for(let i = 0; i<sigLength; i++){
        verifySignature3([rootStateArr[i].account, rootStateArr[i].root], '0x'+rootStateSigArr[i].v.toString(16),rootStateSigArr[i].r,rootStateSigArr[i].s);
    }

    // 提交到智能合约中
}


// 测试加权选举概率
function testRd() {
    let W = [2,5,1,6,9,4,18,3];
    console.log(testRandom())
    let P = [];
    let P1 = [];
    let all = 0;
    for(let i = 0; i<W.length; i++){
        all += W[i];
    }
    console.log("------理想概率-------")
    for(let i = 0; i<W.length; i++){
        P.push(W[i]/all);
        P1.push(0);
    }
    console.log(P)
    for(let i = 0; i<500; i++){
        P1[testRandom()] += 1; 
    }
    for(let i = 0; i<W.length; i++){
        P1[i] = P1[i] / 500;
    }
    console.log("------真实概率-------")
    console.log(P1);
}

function testRandom() {
    let W = [2,5,1,6,9,4,18,3];
    let vector = [];
    let temp = 0;
    for(let i = 0; i<W.length; i++){
        temp += W[i];
        vector.push(temp);
    }
    let rd = Math.ceil(Math.random()*temp);
    for(let i = 0; i<vector.length; i++){
        if(rd <= vector[i]){
            return i;
        }
    }
}

function gasTestCost(gasUsed,gasPrice) {
    let localGasCostWei = gasUsed.mul(gasPrice);
    let localGasCostETH = web3.utils.fromWei(localGasCostWei, 'ether');
    return localGasCostETH * 25000;
}

module.exports = { paymentType, 
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
};