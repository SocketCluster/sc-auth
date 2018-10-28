var jwt = require('jsonwebtoken');

var scErrors = require('sc-errors');
var InvalidArgumentsError = scErrors.InvalidArgumentsError;

var AuthEngine = function () {};

AuthEngine.prototype.verifyToken = function (signedToken, key, options) {
  options = options || {};
  var jwtOptions = cloneObject(options);
  delete jwtOptions.async;
  delete jwtOptions.socket;

  if (options.async) {
    if (typeof signedToken === 'string' || signedToken == null) {
      return new Promise((resolve, reject) => {
        jwt.verify(signedToken || '', key, jwtOptions, (err, token) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(token);
        });
      });
    }
    return Promise.reject(new InvalidArgumentsError('Invalid token format - Token must be a string'));
  }
  if (typeof signedToken === 'string' || signedToken == null) {
    return jwt.verify(signedToken || '', key, jwtOptions);
  }
  throw new InvalidArgumentsError('Invalid token format - Token must be a string');
};

AuthEngine.prototype.signToken = function (token, key, options) {
  options = options || {};
  var jwtOptions = cloneObject(options);
  delete jwtOptions.async;
  if (options.async) {
    return new Promise((resolve, reject) => {
      jwt.sign(token, key, jwtOptions, (err, signedToken) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(signedToken);
      });
    });
  }
  return jwt.sign(token, key, jwtOptions);
};

function cloneObject(object) {
  var clone = {};
  Object.keys(object || {}).forEach(function (key) {
    clone[key] = object[key];
  });
  return clone;
}

module.exports.AuthEngine = AuthEngine;
