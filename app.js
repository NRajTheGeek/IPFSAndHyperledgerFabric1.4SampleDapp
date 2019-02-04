"use strict";

require("dotenv").config();

var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var http = require("http");
var fs = require("fs");
var path = require("path");
var swaggerUi = require("swagger-ui-express");
var yaml = require("js-yaml");
var log4js = require("log4js");
var logger = log4js.getLogger();
var bodyParser = require("body-parser");
require("./configs/envs/config.json");
require("./config.js");

var indexRouter = require("./routes/index");
var usersRouter = require("./routes/users");
var channelsRouter = require("./routes/channels");
var chaincodesRouter = require("./routes/chaincodes");
var queriesRouter = require("./routes/queries");
var docRouter = require("./routes/documents");

global.appDir = path.resolve(__dirname).toString();
global.configs = require("./configs/envs/config.json");

var app = express();
var swaggerDoc = yaml.safeLoad(
  fs.readFileSync("./configs/swaggerConfig/swagger.yaml")
);
//correcting swagger host and base path
(function() {
  console.log("updating swagger");
  swaggerDoc.host = configs.baseURL + ":" + configs.appPort;
  swaggerDoc.basePath = "";
})();

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "jade");

app.use(express.json({ limit: "50mb", extended: false }));
//support parsing of application/x-www-form-urlencoded post data
app.use(
  bodyParser.urlencoded({
    extended: false
  })
);
app.use(cookieParser());
// app.use(express.static(path.join(__dirname, "public")));

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept,X-Auth-Token"
  );
  next();
});

//support parsing of application/json type post data
app.use(bodyParser.json({ limit: 52428800, type: "application/json" }));
//support parsing of application/x-www-form-urlencoded post data

// catch 404 and forward to error handler
app.use(function(err, req, res, next) {
  console.log(err);

  next(createError(err, 404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

/**
 * I know its not a good practice but bare with me
 *
 */

function getErrorMessage(field) {
  var response = {
    success: false,
    message: field + " field is missing or Invalid in the request"
  };
  return response;
}

app.use(
  "/v" + configs.version + "/swagger",
  swaggerUi.serve,
  swaggerUi.setup(swaggerDoc)
);

app.use("/", indexRouter);
app.use("/usersAPI", usersRouter);
app.use("/channelsAPI", channelsRouter);
app.use("/chaincodesAPI", chaincodesRouter);
app.use("/queriesAPI", queriesRouter);
app.use("/documentsAPI", docRouter);

/**
 * Get port from environment and store in Express.
 */

var port = normalizePort(process.env.PORT || "3000");
app.set("port", port);

/**
 * Create HTTP server.
 */

var server = http.createServer(app);

server.timeout = 240000;
/**
 * Listen on provided port, on all network interfaces.
 */

server.listen(port);
server.on("error", onError);
server.on("listening", onListening);

/**
 * Normalize a port into a number, string, or false.
 */

function normalizePort(val) {
  var port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error) {
  if (error.syscall !== "listen") {
    throw error;
  }

  var bind = typeof port === "string" ? "Pipe " + port : "Port " + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case "EACCES":
      console.error(bind + " requires elevated privileges");
      process.exit(1);
      break;
    case "EADDRINUSE":
      console.error(bind + " is already in use");
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * Event listener for HTTP server "listening" event.
 */

function onListening() {
  var addr = server.address();
  var bind = typeof addr === "string" ? "pipe " + addr : "port " + addr.port;
  console.log("Listening on " + bind);
}
