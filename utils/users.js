"use strict";

var hfc = require("fabric-client");
var helper = require("./helper");
var log4js = require("log4js");
var logger = log4js.getLogger("Helper");

var registerUserService = async function(username, userOrg, isJson) {
  var secret;
  try {
    var client = await helper.getClientForOrg(userOrg);
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
      secret = await caClient.register(
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
        // success: true,
        var response = {
          secret: secret,
          message: username + " enrolled Successfully"
        };

        var ret = await generateAndPersistUserCredData(
          secret,
          username,
          userOrg
        );

        // return response
        return {
          err: null,
          data: response
        };
      }
    } else {
      return {
        err: "User was not enrolled ",
        data: null
      };
      // throw new Error("User was not enrolled ");
    }
  } catch (error) {
    logger.error(
      "Failed to get registered user: %s with error: %s",
      username,
      error.toString()
    );
    return {
      err: "failed " + error.toString(),
      data: null
    };
  }
};

var generateAndPersistUserCredData = async function(
  enrollmentSecret,
  uuid,
  org
) {
  var keyPair = await helper.generateRSAKeyPair();
  var pub_k = keyPair.data.RSAPublicKey;
  var pri_k = keyPair.data.RSAPrivateKey;

  var encryptedRSAPrivKey = helper.aesSymmetricEncryption(
    enrollmentSecret,
    pri_k
  );

  var content = {};
  content.rsaPublicKey = pub_k;
  content.encryptedRsaPrivKey = encryptedRSAPrivKey;

  helper
    .hashingData(enrollmentSecret)
    .then(async hashedEnrollmentOb => {
      var userData = {
        secret: hashedEnrollmentOb.data,
        privRSA: encryptedRSAPrivKey,
        pubRSA: pub_k,
        org: org
      };

      await helper.checkAndPersistUser(uuid, userData);
      return true;
    })
    .catch(errOb => {
      console.log(
        "Failed to get public key from keystore of user: " +
          uuid +
          " error: " +
          errOb.err
      );
      return false;
    });
};

module.exports = {
  registerUserService
};
