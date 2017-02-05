var jwt = require('jsonwebtoken');

var scErrors = require('sc-errors');
var InvalidArgumentsError = scErrors.InvalidArgumentsError;

var AuthEngine = function () {};

AuthEngine.prototype.verifyToken = function (signedToken, key, options, callback) {
  options = options || {};
  var jwtOptions = cloneObject(options);
  delete jwtOptions.async;
  if (typeof signedToken == 'string' || signedToken == null) {

    if (options.async) {
      jwt.verify(signedToken || '', key, jwtOptions, callback);
    } else {
      var err = null;
      var token;
      try {
        token = jwt.verify(signedToken || '', key, jwtOptions);
      } catch (error) {
        err = error;
      }
      if (err) {
        callback(err);
      } else {
        callback(null, token);
      }
    }
  } else {
    var err = new InvalidArgumentsError('Invalid token format - Token must be a string');
    callback(err);
  }
};

AuthEngine.prototype.signToken = function (token, key, options, callback) {
  options = options || {};
  var jwtOptions = cloneObject(options);
  delete jwtOptions.async;

  if (options.async) {
    jwt.sign(token, key, jwtOptions, callback);
  } else {
    var signedToken = jwt.sign(token, key, jwtOptions);
    callback(null, signedToken);
  }
};

function cloneObject(object) {
  var clone = {};
  Object.keys(object || {}).forEach(function (key) {
    clone[key] = object[key];
  });
  return clone;
}

module.exports.AuthEngine = AuthEngine;
