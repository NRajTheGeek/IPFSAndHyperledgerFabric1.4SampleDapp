"use strict";
var express = require("express");
var router = express.Router();
var helper = require("../utils/helper");
var usersService = require("../utils/users");

// Register and enroll user
router.post("/users", function(req, res) {
  var username = req.body.username;
  var orgName = req.body.orgName;

  console.log(req.body);
  

  if (!username) {
    res.json(helper.getErrorMessage("'username'"));
    return;
  }
  if (!orgName) {
    res.json(helper.getErrorMessage("'orgName'"));
    return;
  }

  usersService.registerUserService(username, orgName, true).then(response => {
    // helper.getRegisteredUsers(username, orgName, true).then(function(response) {
    if (response.data && typeof !response.err) {
      res.json(response);
    } else {
      res.json({
        success: false,
        message: response
      });
    }
  });
});

/* GET users listing. */
router.get("/", function(req, res, next) {
  res.send("respond with a resource");
});

module.exports = router;
