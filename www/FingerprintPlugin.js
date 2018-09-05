var exec = require('cordova/exec');

exports.authenticate = function (pin, success, error) {
    exec(success, error, 'FingerprintPlugin', 'authenticate', [pin]);
};