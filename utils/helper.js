"use strict";
var log4js = require("log4js");
var logger = log4js.getLogger("Helper");
logger.level = "DEBUG";

var crypto = require("crypto");

var userModel = require("../models/users");
var docModel = require("../models/documents");

var path = require("path");
var util = require("util");

var hfc = require("fabric-client");
hfc.setLogger(logger);
async function getClientForOrg(userorg, username) {
  logger.debug("getClientForOrg - ****** START %s %s", userorg, username);
  // get a fabric client loaded with a connection profile for this org
  let config = "-connection-profile-path";

  // build a client context and load it with a connection profile
  // lets only load the network settings and save the client for later
  let client = hfc.loadFromConfig(hfc.getConfigSetting("network" + config));

  // This will load a connection profile over the top of the current one one
  // since the first one did not have a client section and the following one does
  // nothing will actually be replaced.
  // This will also set an admin identity because the organization defined in the
  // client section has one defined
  client.loadFromConfig(hfc.getConfigSetting(userorg + config));

  // this will create both the state store and the crypto store based
  // on the settings in the client section of the connection profile
  await client.initCredentialStores();

  // The getUserContext call tries to get the user from persistence.
  // If the user has been saved to persistence then that means the user has
  // been registered and enrolled. If the user is found in persistence
  // the call will then assign the user to the client object.
  if (username) {
    let user = await client.getUserContext(username, true);
    if (!user) {
      throw new Error(util.format("User was not found :", username));
    } else {
      logger.debug("User %s was found to be registered and enrolled", username);
    }
  }
  logger.debug("getClientForOrg - ****** END %s %s \n\n", userorg, username);

  return client;
}

var getRegisteredUser = async function(username, userOrg, isJson) {
  try {
    var client = await getClientForOrg(userOrg);
    logger.debug("Successfully initialized the credential stores");
    // client can now act as an agent for organization Org1
    // first check to see if the user is already enrolled
    var user = await client.getUserContext(username, true);
    if (user && user.isEnrolled()) {
      logger.info("Successfully loaded member from persistence");
    } else {
      // user was not enrolled, so we will need an admin user object to register
      logger.info(
        "User %s was not enrolled, so we will need an admin user object to register",
        username
      );
      var admins = hfc.getConfigSetting("admins");
      let adminUserObj = await client.setUserContext({
        username: admins[0].username,
        password: admins[0].secret
      });
      let caClient = client.getCertificateAuthority();
      let secret = await caClient.register(
        {
          enrollmentID: username,
          affiliation: userOrg.toLowerCase() + ".department1"
        },
        adminUserObj
      );
      logger.debug("Successfully got the secret for user %s", username);
      user = await client.setUserContext({
        username: username,
        password: secret
      });
      logger.debug(
        "Successfully enrolled username %s  and setUserContext on the client object",
        username
      );
    }
    if (user && user.isEnrolled) {
      if (isJson && isJson === true) {
        var response = {
          success: true,
          secret: user._enrollmentSecret,
          message: username + " enrolled Successfully"
        };
        return response;
      }
    } else {
      throw new Error("User was not enrolled ");
    }
  } catch (error) {
    logger.error(
      "Failed to get registered user: %s with error: %s",
      username,
      error.toString()
    );
    return "failed " + error.toString();
  }
};

var setupChaincodeDeploy = function() {
  process.env.GOPATH = path.join(
    __dirname,
    hfc.getConfigSetting("CC_SRC_PATH")
  );
};

var getLogger = function(moduleName) {
  var logger = log4js.getLogger(moduleName);
  // logger.setLevel('DEBUG');
  return logger;
};

var bcrypt = require("bcrypt");
var NodeRSA = require("node-rsa");

function getErrorMessage(field) {
  var response = {
    success: false,
    message: field + " field is missing or Invalid in the request"
  };
  return response;
}

var generateRSAKeyPair = function() {
  return new Promise((resolve, reject) => {
    var key = new NodeRSA();
    // 512 bit RSA key is more than enough for this demo
    key.generateKeyPair(512);

    var pub_k = key.exportKey("pkcs8-public-pem");
    var pri_k = key.exportKey("pkcs8-private-pem");

    var keyPair = {
      RSAPrivateKey: pri_k,
      RSAPublicKey: pub_k
    };
    resolve({
      err: null,
      data: keyPair
    });
  });
};

bcrypt.genSaltPromised = util.promisify(bcrypt.genSalt);

var getSalt = function(saltRounds) {
  return new Promise((resolve, reject) => {
    bcrypt
      .genSaltPromised(saltRounds)
      .then(salt => {
        resolve({
          err: null,
          data: salt
        });
      })
      .catch(err => {
        reject({ err: err, data: null });
      });
  });
};

bcrypt.hashPromised = util.promisify(bcrypt.hash);

var generateHash = function(toBeHashed, salt) {
  return new Promise((resolve, reject) => {
    bcrypt
      .hashPromised(toBeHashed, salt)
      .then(hash => {
        resolve({
          err: null,
          data: hash
        });
      })
      .catch(err => {
        reject({
          err: err,
          data: null
        });
      });
  });
};

var hashingData = function(toBeHashed) {
  return new Promise((resolve, reject) => {
    const saltRounds = 10;

    getSalt(saltRounds)
      .then(saltOb => {
        return generateHash(toBeHashed, saltOb.data);
      })
      .then(resultOb => {
        resolve({
          err: null,
          data: resultOb.data
        });
      })
      .catch(errOb => {
        reject({
          err: errOb.err,
          data: null
        });
      });
  });
};

var checkAndPersistUser = function(userName, userData) {
  return new Promise((resolve, reject) => {
    userModel.getUserByUserName(userName).then(async userDetail => {
      if (userDetail.data) {
        resolve({
          err: null,
          data: "user already saved"
        });
      } else {
        var users = await userModel.getUsers();
        users.data[userName] = userData;
        let ret = await userModel.saveUser(users.data);

        resolve({
          err: null,
          data: ret.data
        });
      }
    });
  });
};

var checkAndPersistDoc = function(docHash, docJSON) {
  return new Promise((resolve, reject) => {
    docModel.getDocumentsByDocHash(docHash).then(async docDetail => {
      if (docDetail.data) {
        resolve({
          err: null,
          data: "doc already saved"
        });
      } else {
        var docs = await docModel.getDocuments();
        docs.data[docHash] = docJSON[docHash];
        let ret = await docModel.saveDocument(docs.data);

        resolve({
          err: null,
          data: ret.data
        });
      }
    });
  });
};

var checkAndPersistDocument = function(docHash, docData) {
  return new Promise((resolve, reject) => {
    docModel.getDocumentsByDocHash(docHash).then(async docDetail => {
      if (docDetail.data) {
        resolve({
          err: null,
          data: "doc already saved"
        });
      } else {
        var docs = await docModel.getDocuments();
        docs.data[docHash] = docData;
        let ret = await docModel.saveUser(docs.data);

        resolve({
          err: null,
          data: ret.data
        });
      }
    });
  });
};

var aesSymmetricEncryption = function(key, data) {
  return crypto.createCipher("aes-256-ctr", key).update(data, "ust8", "hex");
};

var aesSymmetricDecryption = function(encryptedData, key) {
  if (typeof encryptedData == "undefined" || encryptedData.length <= 0) {
    throw new Error("data must not be defined");
  }

  if (typeof key == "undefined" || key.length <= 0) {
    throw new Error("key must not be defined");
  }

  return crypto
    .createDecipher("aes-256-ctr", key)
    .update(encryptedData, "hex", "utf-8");
};

module.exports = {
  getClientForOrg,
  getLogger,
  setupChaincodeDeploy,
  getRegisteredUser,

  generateRSAKeyPair,
  hashingData,
  checkAndPersistUser,
  checkAndPersistDoc,
  checkAndPersistDocument,
  aesSymmetricEncryption,
  aesSymmetricDecryption
};
