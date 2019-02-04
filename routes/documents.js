"use strict";
var express = require("express");
var router = express.Router();

var docService = require("../utils/docService");

router.post("/uploadDocToBePublished", function(req, res, callback) {
  var documentBinary = req.body.document;
  var publisherId = req.body.pubisherId;
  var userId = req.body.userId;

  docService.uploadDocumentToIPFS(documentBinary, publisherId, userId, res);
});

router.post(
  "/viewDoc/docHash/:docHash/CID/:CID",
  function(req, res, callback) {
    var docHash = req.params.docHash;
    var CID = req.params.CID;

    var viewerUuid = req.body.viewerUuid;
    var fabricSecret = req.body.fabricSecret;

    docService.viewDocument(docHash, CID, viewerUuid, fabricSecret, res);
  }
);

router.post(
  "/sendDocForVerification/channels/:channelName/chaincodeName/:chaincodeName",
  function(req, res, callback) {
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    var peers = req.body.peers;

    var username = req.body.userName;
    var orgName = req.body.orgName;
    var docHash = req.body.docHash;
    var publisherUUID = req.body.publisherUUID;
    var ownerUUID = req.body.ownerUUID;
    var DocumentStatus = req.body.DocumentStatus;
    var OwnerPublicKey = req.body.OwnerPublicKey;
    var VerifierPublicKey = req.body.VerifierPublicKey;

    docService.sendDocumentForVerification(
      username,
      orgName,
      docHash,
      channelName,
      chaincodeName,
      peers,
      publisherUUID,
      ownerUUID,
      DocumentStatus,
      OwnerPublicKey,
      VerifierPublicKey,
      res
    );
  }
);

router.post(
  "/updateDocStatus/channels/:channelName/chaincodeName/:chaincodeName",
  function(req, res, callback) {
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    var peers = req.body.peers;

    var userName = req.body.userName;
    var orgName = req.body.orgName;
    var docHash = req.body.docHash;
    var DocumentStatus = req.body.DocumentStatus;

    docService.updateDocStatus(
      userName,
      orgName,
      docHash,
      channelName,
      chaincodeName,
      peers,
      DocumentStatus,
      res
    );
  }
);

router.get(
  "/queryDocByStatus/channels/:channelName/chaincodeName/:chaincodeName/peers/:peer/docStatus/:DocumentStatus/userName/:userName/orgName/:orgName",
  function(req, res, callback) {
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    var peers = [];

    peers.push(req.params.peer);

    var userName = req.params.userName;
    var orgName = req.params.orgName;
    var DocumentStatus = req.params.DocumentStatus;

    docService.queryDocByStatus(
      userName,
      orgName,
      channelName,
      chaincodeName,
      peers,
      DocumentStatus,
      res
    );
  }
);

router.get(
  "/queryDocByHash/channels/:channelName/chaincodeName/:chaincodeName/peers/:peer/docHash/:DocumentHash/userName/:userName/orgName/:orgName",
  function(req, res, callback) {
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    var peers = [];
    peers.push(req.params.peer)

    var userName = req.params.userName;
    var orgName = req.params.orgName;
    var DocumentHash = req.params.DocumentHash;

    docService.queryDocByDocHash(
      userName,
      orgName,
      channelName,
      chaincodeName,
      peers,
      DocumentHash,
      res
    );
  }
);

router.post("/shareDoc", function(req, res, callback) {
  var docHash = req.body.documentHash;
  var CID = req.body.shareDocCID;

  var ownerUUID = req.body.ownerUUID;
  var ownerFabricSecret = req.body.ownerFabricSecret;
  var uuidToBeSharedWith = req.body.uuidToBeSharedWith;

  docService.shareDocumentAccess(
    docHash,
    CID,
    ownerUUID,
    ownerFabricSecret,
    uuidToBeSharedWith,
    res
  );
});

module.exports = router;
