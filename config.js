var util = require("util");
var path = require("path");
var hfc = require("fabric-client");

var file = "network-config%s.yaml";

var env = process.env.TARGET_NETWORK;
if (env) file = util.format(file, "-" + env);
else file = util.format(file, "");
// indicate to the application where the setup file is located so it able
// to have the hfc load it to initalize the fabric client instance
console.log("=========================== file ============================");
console.log(path.join(__dirname, "utils", "org1.yaml"));

hfc.setConfigSetting(
  "network-connection-profile-path",
  path.join(__dirname, "utils", file)
);
hfc.setConfigSetting(
  "Org1-connection-profile-path",
  path.join(__dirname, "utils", "org1.yaml")
);
hfc.setConfigSetting(
  "Org2-connection-profile-path",
  path.join(__dirname, "utils", "org2.yaml")
);
// some other settings the application might need to know
hfc.addConfigFile(path.join(__dirname, "./configs/envs/config.json"));
