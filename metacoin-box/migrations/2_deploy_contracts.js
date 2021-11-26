const ConvertLib = artifacts.require("ConvertLib");
const MetaCoin = artifacts.require("MetaCoin");
const MerkleMultiProof = artifacts.require("MerkleMultiProof")

module.exports = function(deployer) {
  deployer.deploy(ConvertLib);
  deployer.deploy(MerkleMultiProof)
  deployer.link(ConvertLib, MetaCoin);
  deployer.deploy(MetaCoin);
};
