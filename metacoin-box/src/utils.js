const Web3  = require('web3');
const web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:8545'));

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
    ).slice(2))

    return offchainSign(encodedMsg, privateKey)
}

module.exports = { paymentType, hexToBytes, offchainSign, signRawMessage};