"use strict"
var express = require('express');
var router = express.Router();
var query = require("../utils/query.js");
var helper = require("../utils/helper");


// Query on chaincode on target peers
router.get("/channels/:channelName/chaincodes/:chaincodeName", function(req, res) {
	console.log("==================== QUERY BY CHAINCODE ==================");
  var channelName = req.params.channelName;
  var chaincodeName = req.params.chaincodeName;
  let args = req.query.args;
  let fcn = req.query.fcn;
  let peer = req.query.peer;

  console.log("channelName : " + channelName);
  console.log("chaincodeName : " + chaincodeName);
  console.log("fcn : " + fcn);
  console.log("args : " + args);

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
  args = args.replace(/'/g, '"');
  args = JSON.parse(args);
  console.log(args);

  query
    .queryChaincode(
      peer,
      channelName,
      chaincodeName,
      args,
      fcn,
      req.username,
      req.orgname
    )
    .then(function(message) {
      res.send(message);
    });
});
//  Query Get Block by BlockNumber
router.get("/channels/:channelName/blocks/:blockId", function(req, res) {
  console.log("==================== GET BLOCK BY NUMBER ==================");
  let blockId = req.params.blockId;
  let peer = req.query.peer;
  console.log("channelName : " + req.params.channelName);
  console.log("BlockID : " + blockId);
  console.log("Peer : " + peer);
  if (!blockId) {
    res.json(helper.getErrorMessage("'blockId'"));
    return;
  }

  query
    .getBlockByNumber(peer, blockId, req.username, req.orgname)
    .then(function(message) {
      res.send(message);
    });
});
// Query Get Transaction by Transaction ID
router.get("/channels/:channelName/transactions/:trxnId", function(req, res) {
  console.log(
    "================ GET TRANSACTION BY TRANSACTION_ID ======================"
  );
  console.log("channelName : " + req.params.channelName);
  let trxnId = req.params.trxnId;
  let peer = req.query.peer;
  if (!trxnId) {
    res.json(helper.getErrorMessage("'trxnId'"));
    return;
  }

  query
    .getTransactionByID(peer, trxnId, req.username, req.orgname)
    .then(function(message) {
      res.send(message);
    });
});
// Query Get Block by Hash
router.get("/channels/:channelName/blocks", function(req, res) {
  console.log("================ GET BLOCK BY HASH ======================");
  console.log("channelName : " + req.params.channelName);
  let hash = req.query.hash;
  let peer = req.query.peer;
  if (!hash) {
    res.json(helper.getErrorMessage("'hash'"));
    return;
  }

  query
    .getBlockByHash(peer, hash, req.username, req.orgname)
    .then(function(message) {
      res.send(message);
    });
});
//Query for Channel Information
router.get("/channels/:channelName", function(req, res) {
  console.log(
    "================ GET CHANNEL INFORMATION ======================"
  );
  console.log("channelName : " + req.params.channelName);
  let peer = req.query.peer;

  query.getChainInfo(peer, req.username, req.orgname).then(function(message) {
    res.send(message);
  });
});
// Query to fetch all Installed/instantiated chaincodes
router.get("/chaincodes", function(req, res) {
  var peer = req.query.peer;
  var installType = req.query.type;
  //TODO: add Constnats
  if (installType === "installed") {
    console.log(
      "================ GET INSTALLED CHAINCODES ======================"
    );
  } else {
    console.log(
      "================ GET INSTANTIATED CHAINCODES ======================"
    );
  }

  query
    .getInstalledChaincodes(peer, installType, req.username, req.orgname)
    .then(function(message) {
      res.send(message);
    });
});
// Query to fetch channels
router.get("/channels", function(req, res) {
  console.log("================ GET CHANNELS ======================");
  console.log("peer: " + req.query.peer);
  var peer = req.query.peer;
  if (!peer) {
    res.json(helper.getErrorMessage("'peer'"));
    return;
  }

  query.getChannels(peer, req.username, req.orgname).then(function(message) {
    res.send(message);
  });
});


module.exports = router;
