"use strict"
var express = require("express");
var router = express.Router();
var helper = require("../utils/helper");
var channels = require('../utils/create-channel');
var join = require("../utils/join-channel.js");
var updateAnchorPeers = require('../utils/update-anchor-peers.js');

// Create Channel
router.post("/channels", function(req, res) {
  console.log("<<<<<<<<<<<<<<<<< C R E A T E  C H A N N E L >>>>>>>>>>>>>>>>>");
  console.log("End point : /channels");
  var channelName = req.body.channelName;
  var channelConfigPath = req.body.channelConfigPath;
  var userName = req.body.userName;
  var orgName = req.body.orgName;
  console.log("Channel name : " + channelName);
  console.log("channelConfigPath : " + channelConfigPath); //../artifacts/channel/mychannel.tx
  if (!channelName) {
    res.json(helper.getErrorMessage("'channelName'"));
    return;
  }
  if (!channelConfigPath) {
    res.json(helper.getErrorMessage("'channelConfigPath'"));
    return;
  }

  channels
    .createChannel(channelName, channelConfigPath, userName, orgName)
    .then(function(message) {
      res.send(message);
    });
});

// Join Channel
router.post("/channels/:channelName/peers", function(req, res) {
  console.log("<<<<<<<<<<<<<<<<< J O I N  C H A N N E L >>>>>>>>>>>>>>>>>");
  var channelName = req.params.channelName;
  var peers = req.body.peers;
  var userName = req.body.userName;
  var orgName = req.body.orgName;
  console.log("channelName : " + channelName);
  console.log("peers : " + peers);
  if (!channelName) {
    res.json(helper.getErrorMessage("'channelName'"));
    return;
  }
  if (!peers || peers.length == 0) {
    res.json(helper.getErrorMessage("'peers'"));
    return;
  }

  join
    .joinChannel(channelName, peers, userName, orgName)
    .then(function(message) {
      res.send(message);
    });
});

// Update anchor peers
router.post('/channels/:channelName/anchorpeers', async function(req, res) {
	console.log('==================== UPDATE ANCHOR PEERS ==================');
	var channelName = req.params.channelName;
  var configUpdatePath = req.body.configUpdatePath;
  var userName = req.body.userName;
  var orgName = req.body.orgName;

	console.log('Channel name : ' + channelName);
  console.log('configUpdatePath : ' + configUpdatePath);
  
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!configUpdatePath) {
		res.json(getErrorMessage('\'configUpdatePath\''));
		return;
	}

	let message = await updateAnchorPeers.updateAnchorPeers(channelName, configUpdatePath, userName, orgName);
	res.send(message);
});

module.exports = router;
