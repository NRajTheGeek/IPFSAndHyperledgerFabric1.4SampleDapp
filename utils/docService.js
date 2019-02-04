"use strict";

const ipfsClient = require("ipfs-http-client");
const log4js = require("log4js");
const logger = log4js.getLogger("Helper");
logger.level = "info";
const NodeRSA = require("node-rsa");
const hfc = require("fabric-client");
hfc.setLogger(logger);
const sha256 = require("js-sha256").sha256;

const helper = require("./helper.js");
const invokeChaincode = require("../utils/invoke-transaction");
const query = require("../utils/query");
const UsersModel = require("../models/users");
const docModel = require("../models/documents");

// +++++++++++++++++++++++++++++++++++++ IPFS +++++++++++++++++++++++++++++++++++++

// connect to ipfs daemon API server
const ipfs = ipfsClient("localhost", "5001", { protocol: "http" });
const utils = require("util");
ipfs.addFromFs = utils.promisify(ipfs.addFromFs);
ipfs.add = utils.promisify(ipfs.add);

ipfs.get = utils.promisify(ipfs.get);

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

var uploadDocumentToIPFS = function(document, publisherId, userId, res) {
  // 1. first fetch the user and the verifier by their names
  // to basically capture their RSA public keys
  //  then encrypt the document binary in two folds
  // 2. calculate sha256 of the docuent binary
  // 3. encrypt with the public key of the publisher and then with symmetric key of the system
  // put the hash_digest to the IPFS and get the CID of this document
  // 4. encrypt with the public key of the owner user and then with symmetric key of the system
  // put the hash_digest to the IPFS and get the CID of this document
  // 5. put this doc hash and respective CID onto the documents model

  var sha256OfDoc = _getSHA256OfData(document);
  var collection = {};

  UsersModel.getUserByUserName(publisherId)
    .then(publisherDataOb => {
      let publisherData = publisherDataOb.data;

      let encryptedByPublisher = _RSAEncryptData(
        document,
        publisherData.pubRSA
      );
      let symmetricEncryptedData = helper.aesSymmetricEncryption(
        process.env.APP_ENC_SYMMETRIC_KEY,
        encryptedByPublisher
      );

      return _publlishToIPFS(symmetricEncryptedData);
    })
    .then(CIDByPublisher => {
      collection.CIDByPublisher = CIDByPublisher.data;
      return UsersModel.getUserByUserName(userId);
    })
    .then(userDataOb => {
      let userData = userDataOb.data;

      let encryptedByUser = _RSAEncryptData(document, userData.pubRSA);
      let symmetricEncryptedData = helper.aesSymmetricEncryption(
        process.env.APP_ENC_SYMMETRIC_KEY,
        encryptedByUser
      );

      return _publlishToIPFS(symmetricEncryptedData);
    })
    .then(CIDByUser => {
      collection.CIDByUser = CIDByUser.data;

      let docJSONModel = _BuildUpDocModel(
        sha256OfDoc,
        userId,
        collection.CIDByUser,
        publisherId,
        collection.CIDByPublisher
      );

      return helper.checkAndPersistDoc(sha256OfDoc, docJSONModel);
    })
    .then(savedDocRetOb => {
      res.send({
        saveresponse: savedDocRetOb.data,
        docHash: sha256OfDoc,
        CIDByPublisher: collection.CIDByPublisher,
        CIDByUser: collection.CIDByUser
      });
    })
    .catch(errOb => {
      console.log(errOb);

      res.send(errOb.err);
    });
};

var viewDocument = function(documentHash, CID, viewerUuid, fabricSecret, res) {
  // 1. check the details and access
  // 2. fetch data from the ipfs which will be encrypted by the symmetric key => public key
  // 3. decrypt symmetricaly
  // 4. decrypt by private key
  // 5. return the binary data

  var content = {};

  UsersModel.getUserByUserName(viewerUuid)
    .then(userDataOb => {
      var userData = userDataOb.data;
      var decryptedPrivateKey = helper.aesSymmetricDecryption(
        userData.privRSA,
        fabricSecret
      );
      content.privateKey = decryptedPrivateKey;

      return docModel.getDocumentsByDocHash(documentHash);
    })
    .then(dataOb => {
      let docData = dataOb.data;

      if (_validateCIDForDocHash(docData, CID)) {
        content.docDataOb = docData;
        return _fetchFromIPFS(CID);
      } else {
        return res.send(new Error("doc does not exists"));
      }
    })
    .then(dataFromIPFS => {
      var DocFromIPFS = dataFromIPFS.data[0].content.toString();
      var aesDecrypted = helper.aesSymmetricDecryption(
        DocFromIPFS,
        process.env.APP_ENC_SYMMETRIC_KEY
      );

      var decryptedDocBinary = _RSADecryptData(
        aesDecrypted,
        content.privateKey
      );

      res.send(decryptedDocBinary);
    })
    .catch(errOb => {
      console.log(errOb.err ? errOb.err : errOb);
      res.send(errOb.err ? errOb.err : errOb);
    });
};

var sendDocumentForVerification = function(
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
) {
  var fcn = "init_document";
  var args = [];
  args.push(channelName);
  args.push(publisherUUID);
  args.push(ownerUUID);
  args.push(docHash);
  args.push(DocumentStatus);
  args.push(OwnerPublicKey);
  args.push(VerifierPublicKey);

  invokeChaincode
    .invokeChaincode(
      peers,
      channelName,
      chaincodeName,
      fcn,
      args,
      username,
      orgName
    )
    .then(invokeCallRet => {
      res.send(invokeCallRet);
    })
    .catch(err => {
      res.send(err);
    });
};

var updateDocStatus = function(
  username,
  orgName,
  docHash,
  channelName,
  chaincodeName,
  peers,
  DocumentStatus,
  res
) {
  var fcn = "update_document";
  var args = [];
  args.push(docHash);
  args.push(DocumentStatus);

  invokeChaincode
    .invokeChaincode(
      peers,
      channelName,
      chaincodeName,
      fcn,
      args,
      username,
      orgName
    )
    .then(invokeCallRet => {
      res.send(invokeCallRet);
    })
    .catch(err => {
      res.send(err);
    });
};

var queryDocByStatus = function(
  username,
  orgName,
  channelName,
  chaincodeName,
  peers,
  DocumentStatus,
  res
) {
  var fcn = "queryDocumentsByStatus";
  var args = [];
  args.push(channelName);
  args.push(DocumentStatus);

  query
    .queryChaincode(
      peers,
      channelName,
      chaincodeName,
      args,
      fcn,
      username,
      orgName
    )
    .then(invokeCallRet => {
      res.send(invokeCallRet);
    })
    .catch(err => {
      res.send(err);
    });
};

var queryDocByDocHash = function(
  username,
  orgName,
  channelName,
  chaincodeName,
  peers,
  DocHash,
  res
) {
  var fcn = "queryDocumentStatusByHash";
  var args = [];
  args.push(DocHash);

  query
    .queryChaincode(
      peers,
      channelName,
      chaincodeName,
      args,
      fcn,
      username,
      orgName
    )
    .then(invokeCallRet => {
      res.send(invokeCallRet);
    })
    .catch(err => {
      res.send(err);
    });
};

var shareDocumentAccess = function(
  documentHash,
  CID,
  ownerUuid,
  ownerFabricSecret,
  uuidToBeSharedWith,
  res
) {
  // TODO: 1. check the details of owner and docHash and CID and access to it of owner
  // TODO: 2. fetch data from the ipfs which will be decrypted by the symmetric key => private key
  // TODO: 3. decrypt symmetricaly
  // TODO: 4. decrypt by private key
  // TODO: 5. return the binary data

  var content = {};

  UsersModel.getUserByUserName(ownerUuid)
    .then(userDataOb => {
      var userData = userDataOb.data;
      var decryptedPrivateKey = helper.aesSymmetricDecryption(
        userData.privRSA,
        ownerFabricSecret
      );
      content.privateKey = decryptedPrivateKey;

      return docModel.getDocumentsByDocHash(documentHash);
    })
    .then(dataOb => {
      let docData = dataOb.data;

      if (_validateCIDForDocHash(docData, CID)) {
        content.docDataOb = docData;
        return _fetchFromIPFS(CID);
      } else {
        return res.send(new Error("doc does not exists"));
      }
    })
    .then(dataFromIPFS => {
      var DocFromIPFS = dataFromIPFS.data[0].content.toString();
      var aesDecrypted = helper.aesSymmetricDecryption(
        DocFromIPFS,
        process.env.APP_ENC_SYMMETRIC_KEY
      );

      var decryptedDocBinary = _RSADecryptData(
        aesDecrypted,
        content.privateKey
      );

      content.decryptedDocBinary = decryptedDocBinary;
      return UsersModel.getUserByUserName(uuidToBeSharedWith);
    })
    .then(sharereDataOb => {
      let sharereData = sharereDataOb.data;

      let encryptedBySharer = _RSAEncryptData(
        content.decryptedDocBinary,
        sharereData.pubRSA
      );
      let symmetricEncryptedData = helper.aesSymmetricEncryption(
        process.env.APP_ENC_SYMMETRIC_KEY,
        encryptedBySharer
      );

      return _publlishToIPFS(symmetricEncryptedData);
    })
    .then(CIDBySharer => {
      content.CIDBySharer = CIDBySharer.data;

      content.sharedDocModel = _BuildShareDocModel(
        ownerUuid,
        uuidToBeSharedWith,
        content.CIDBySharer,
        content.docDataOb
      );

      return docModel.getDocuments();
    })
    .then(allDocDataOb => {
      let allDoc = allDocDataOb.data;
      allDoc[documentHash] = content.sharedDocModel;
      return docModel.saveDocument(allDoc);
    })
    .then(resDataOb => {
      res.send({
        data: resDataOb.data
      });
    })
    .catch(errOb => {
      console.log(errOb.err ? errOb.err : errOb);
      res.send(errOb.err ? errOb.err : errOb);
    });
};

// ==================================== Private Library ===============================================

var _BuildUpDocModel = function(
  docSHA256,
  userId,
  CIDByUser,
  publisherId,
  CIDByPublisher
) {
  let publisDetailArray = [];
  let publisherCIDObject = {};
  publisherCIDObject[CIDByPublisher] = {};
  publisherCIDObject[CIDByPublisher].publishedBy = publisherId;
  publisherCIDObject[CIDByPublisher].certOwner = userId;
  publisherCIDObject[CIDByPublisher].publicationDate = new Date();
  publisherCIDObject[CIDByPublisher].publicationDescription =
    "this is a digital pub";

  publisDetailArray.push(publisherCIDObject);

  let shareDetailArray = [];
  let userCIDObject = {};
  userCIDObject[CIDByUser] = {};
  userCIDObject[CIDByUser].sharedBy = userId;
  userCIDObject[CIDByUser].sharedWith = "";
  userCIDObject[CIDByUser].sharingDescription = "";

  shareDetailArray.push(userCIDObject);

  let docModel = {};

  docModel[docSHA256] = {};

  docModel[docSHA256].owner = userId;
  docModel[docSHA256].publishDetail = publisDetailArray;
  docModel[docSHA256].shareDetail = shareDetailArray;

  return docModel;
};

var _BuildShareDocModel = function(
  sharedFromId,
  shareredWithId,
  sharedDocCID,
  originalDocJSON
) {
  let newShareObject = {};
  newShareObject[sharedDocCID] = {};
  newShareObject[sharedDocCID].sharedBy = sharedFromId;
  newShareObject[sharedDocCID].sharedWith = shareredWithId;
  newShareObject[sharedDocCID].shareDiscription = "Nice Share";

  originalDocJSON.shareDetail.push(newShareObject);

  return originalDocJSON;
};

var _RSAEncryptData = function(plainTextDataBuffer, RSAPublicKey) {
  let key = new NodeRSA();
  var publicKey = key.importKey(RSAPublicKey, "pkcs8-public-pem");
  // let publicKey = key.importKey(RSAPublicKey, 'components-public');
  return publicKey.encrypt(plainTextDataBuffer, "base64", "utf8");
};

var _RSADecryptData = function(encryptedDataString, RSAPrivateKey) {
  let key = new NodeRSA();
  var privateKey = key.importKey(RSAPrivateKey, "pkcs8-private-pem");
  return privateKey.decrypt(encryptedDataString, "utf8");
};

var _getSHA256OfData = function(textData) {
  return sha256(textData);
};

var _publlishToIPFS = function(textualData) {
  var fileBuff = Buffer(textualData);

  return new Promise((resolve, reject) => {
    ipfs
      .add(fileBuff)
      .then(result => {
        let dataUploaded = result[0].hash;

        resolve({
          err: null,
          data: dataUploaded
        });
      })
      .catch(err => {
        console.log(err);
        reject({
          err: err,
          data: null
        });
      });
  });
};

var _fetchFromIPFS = function(CID) {
  return new Promise((resolve, reject) => {
    ipfs
      .get(CID)
      .then(files => {
        resolve({
          err: null,
          data: files
        });
      })
      .catch(err => {
        console.log(err);
        reject({
          err: err,
          data: null
        });
      });
  });
};

var _validateCIDForDocHash = function(docDataObject, CID) {
  if (_checkObjectKeyInArray(docDataObject.publishDetail, CID)) {
    return true;
  } else if (_checkObjectKeyInArray(docDataObject.shareDetail, CID)) {
    return true;
  } else {
    return false;
  }
};
var _checkObjectKeyInArray = function(objectArray, key) {
  for (let i = 0; i < objectArray.length; i++) {
    if (objectArray[i][key]) {
      return true;
    }
  }
  return false;
};

//=====================================================================================================

module.exports = {
  uploadDocumentToIPFS,
  viewDocument,
  sendDocumentForVerification,
  updateDocStatus,
  queryDocByStatus,
  queryDocByDocHash,
  shareDocumentAccess
};
