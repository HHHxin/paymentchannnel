const ConvertLib = artifacts.require("ConvertLib");
const MetaCoin = artifacts.require("MetaCoin");
const MerkleMultiProof = artifacts.require("MerkleMultiProof");
const MerkleProof = artifacts.require("MerkleProof");

module.exports = function(deployer) {
  deployer.deploy(ConvertLib);
  deployer.deploy(MerkleMultiProof);
  deployer.deploy(MerkleProof);
  deployer.link(ConvertLib, MetaCoin);
  deployer.deploy(MetaCoin);
};
