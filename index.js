var jwt = require('jsonwebtoken');

var scErrors = require('sc-errors');
var InvalidArgumentsError = scErrors.InvalidArgumentsError;


var AuthEngine = function () {};

AuthEngine.prototype.verifyToken = function (signedToken, key, options, callback) {
  if (typeof signedToken == 'string' || signedToken == null) {
    jwt.verify(signedToken || '', key, options, callback);
  } else {
    var err = new InvalidArgumentsError('Invalid token format - Token must be a string');
    callback(err);
  }
};

AuthEngine.prototype.signToken = function (token, key, options, callback) {
  jwt.sign(token, key, options, callback);
};

module.exports.AuthEngine = AuthEngine;
