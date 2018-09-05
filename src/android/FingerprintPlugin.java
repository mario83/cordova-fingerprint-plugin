package cordova-plugin-fingerprintplugin;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This class echoes a string called from JavaScript.
 */
public class FingerprintPlugin extends CordovaPlugin {

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("authenticate")) {
            this.authenticate(callbackContext);
            return true;
        }
        return false;
    }

    private void authenticate(String message, CallbackContext callbackContext) {
        callbackContext.success(message);
        // callbackContext.error("Expected one non-empty string argument.");
    }
}
