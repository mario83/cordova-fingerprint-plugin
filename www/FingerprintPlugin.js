var exec = require('cordova/exec');

var touchid = {
	isAvailable: function(successCallback, errorCallback){
		exec(successCallback, errorCallback, "FingerprintPlugin", "isAvailable", []);
	},
	save: function(key,password, successCallback, errorCallback) {
		exec(successCallback, errorCallback, "FingerprintPlugin", "save", [key,password]);
	},
	verify: function(key,successCallback, errorCallback){
		exec(successCallback, errorCallback, "FingerprintPlugin", "verify", [key]);
	},
	delete: function(key,successCallback, errorCallback){
		exec(successCallback, errorCallback, "FingerprintPlugin", "delete", [key]);
	},
	has: function(key,successCallback, errorCallback){
		exec(successCallback, errorCallback, "FingerprintPlugin", "has", [key]);
	}
};

module.exports = touchid;
