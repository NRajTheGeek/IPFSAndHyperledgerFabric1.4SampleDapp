var path = require("path");
var fs = require("fs");

var saveUser = function(configJSON) {
  return new Promise((resolve, reject)=>{
    let fileData = "";
    const filePath = path.join(__dirname, "users.json");
  
    try {
      const stream = fs.createWriteStream(filePath, { encoding: "utf-8" });
      // passing three params to json.stringify, third param tell writer about the white spaces to maintain
      // to prettify json file in writing to a file
      stream.write(JSON.stringify(configJSON, null, 4));
      stream.end();
      resolve({
          err: null, data: "user updated successfully"
      });
    } catch (err) {
      logger.error(err, err.stack ? err.stack : err);
      reject({err: err, data: null});
    }
  })
};

var getUsers = function() {
  return new Promise(
    (resolve,reject) => {
      let fileData = "";
      const filePath = path.join(__dirname, "users.json");

      try {
        const stream = fs.createReadStream(filePath, { encoding: "utf-8" });
        stream.on("data", data => {
          fileData += data.toString();
        });
        stream.on("end", () => {
          resolve({
            err: null,
            data: JSON.parse(fileData)
          });
        });
      } catch (err) {
        logger.error(err, err.stack ? err.stack : err);
        reject({
          err: err,
          data: null
        });
      }
    })
};

var getUserByUserName = function(userName) {
  return new Promise((resolve, reject)=> {
    let fileData = "";
    const filePath = path.join(__dirname, "users.json");
  
    try {
      const stream = fs.createReadStream(filePath, { encoding: "utf-8" });
      stream.on("data", data => {
        fileData += data.toString();
      });
      stream.on("end", () => {
        var userObject = JSON.parse(fileData)[userName];
        resolve({
            err: null, data: userObject
        });
      });
    } catch (err) {
      logger.error(err, err.stack ? err.stack : err);
      reject({
        err: err, data: null
      });
    }
  })
};

module.exports = {
  saveUser,
  getUsers,
  getUserByUserName
};
