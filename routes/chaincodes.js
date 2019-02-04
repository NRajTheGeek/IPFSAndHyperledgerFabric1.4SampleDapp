"use strict"
var express = require("express");
var router = express.Router();


var helper = require("../utils/helper");

var install = require("../utils/install-chaincode.js");
var instantiate = require("../utils/instantiate-chaincode.js");
var invoke = require("../utils/invoke-transaction.js");

// Install chaincode on target peers
router.post("/chaincodes", function(req, res) {
  console.log("==================== INSTALL CHAINCODE ==================");
  var peers = req.body.peers;
  var chaincodeName = req.body.chaincodeName;
  var chaincodePath = req.body.chaincodePath;
  var chaincodeVersion = req.body.chaincodeVersion;
  var userName = req.body.userName;
  var orgName = req.body.orgName;

  console.log("peers : " + peers); // target peers list
  console.log("chaincodeName : " + chaincodeName);
  console.log("chaincodePath  : " + chaincodePath);
  console.log("chaincodeVersion  : " + chaincodeVersion);
  if (!peers || peers.length == 0) {
    res.json(helper.getErrorMessage("'peers'"));
    return;
  }
  if (!chaincodeName) {
    res.json(helper.getErrorMessage("'chaincodeName'"));
    return;
  }
  if (!chaincodePath) {
    res.json(helper.getErrorMessage("'chaincodePath'"));
    return;
  }
  if (!chaincodeVersion) {
    res.json(helper.getErrorMessage("'chaincodeVersion'"));
    return;
  }

  install
    .installChaincode(
      peers,
      chaincodeName,
      chaincodePath,
      chaincodeVersion,
      "golang",
      userName,
      orgName
    )
    .then(function(message) {
      res.send(message);
    });
});
// Instantiate chaincode on target peers
router.post("/channels/:channelName/chaincodes", function(req, res) {
  console.log("==================== INSTANTIATE CHAINCODE ==================");
  var chaincodeName = req.body.chaincodeName;
  var chaincodeVersion = req.body.chaincodeVersion;
  var channelName = req.params.channelName;
  var fcn = req.body.fcn;
  var args = req.body.args;
  var targets = req.body.peers;
  var userName = req.body.userName;
  var orgName = req.body.orgName;

  if(!fcn) {
    fcn = "";
  }

  console.log("channelName  : " + channelName);
  console.log("chaincodeName : " + chaincodeName);
  console.log("chaincodeVersion  : " + chaincodeVersion);
  console.log("fcn  : " + fcn);
  console.log("args  : " + args);
  if (!chaincodeName) {
    res.json(helper.getErrorMessage("'chaincodeName'"));
    return;
  }
  if (!chaincodeVersion) {
    res.json(helper.getErrorMessage("'chaincodeVersion'"));
    return;
  }
  if (!channelName) {
    res.json(helper.getErrorMessage("'channelName'"));
    return;
  }
  if (!args) {
    res.json(helper.getErrorMessage("'args'"));
    return;
  }
  instantiate
    .instantiateChaincode(
      targets,
      channelName,
      chaincodeName,
      chaincodeVersion,
      fcn,
      "golang",
      args,
      userName,
      orgName
    )
    .then(function(message) {
      res.send(message);
    });
});
// Invoke transaction on chaincode on target peers
router.post("/channels/:channelName/chaincodes/:chaincodeName", function(
  req,
  res
) {
  console.log("==================== INVOKE ON CHAINCODE ==================");
  var peers = req.body.peers;
  var chaincodeName = req.params.chaincodeName;
  var channelName = req.params.channelName;
  var fcn = req.body.fcn;
  var args = req.body.args;
  var userName = req.body.userName;
  var orgName = req.body.orgName;

  console.log("channelName  : " + channelName);
  console.log("chaincodeName : " + chaincodeName);
  console.log("fcn  : " + fcn);
  console.log("args  : " + args);
  if (!chaincodeName) {
    res.json(helper.getErrorMessage("'chaincodeName'"));
    return;
  }
  if (!channelName) {
    res.json(helper.getErrorMessage("'channelName'"));
    return;
  }
  if (!fcn) {
    res.json(helper.getErrorMessage("'fcn'"));
    return;
  }
  if (!args) {
    res.json(helper.getErrorMessage("'args'"));
    return;
  }

  invoke
    .invokeChaincode(
      peers,
      channelName,
      chaincodeName,
      fcn,
      args,
      userName,
      orgName
    )
    .then(function(message) {
      res.send(message);
    });
});

module.exports = router;
