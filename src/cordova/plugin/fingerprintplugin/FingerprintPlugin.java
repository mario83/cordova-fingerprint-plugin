package cordova.plugin.fingerprintplugin;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import android.os.Build;
import android.util.Log;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import cordova.plugin.fingerprintplugin.FingerPrintUtil;

/**
 * This class echoes a string called from JavaScript.
 */
public class FingerprintPlugin extends CordovaPlugin {

	public static final String TAG = "FingerprintAuth";
	
	public Context applicationContext;
	private FingerprintManager fingerPrintManager;
	private FingerPrintUtil fingerPrintUtil;
	
	public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(TAG, "initialize: FingerprintAuth");

        applicationContext = cordova.getActivity().getApplicationContext();
        fingerPrintManager = getContext().getSystemService(FingerprintManager.class);
        
        fingerPrintUtil = new FingerPrintUtil(applicationContext,fingerPrintManager);
	}
	
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    	
    	Log.v(TAG, "execute: action"+action);
        if (action.equals("authenticate")) {
            this.authenticate(callbackContext);
            Log.v(TAG, "execute: this.authenticate");
            return true;
        }
        return false;
    }
    
    
    private void authenticate(CallbackContext callbackContext) {
    	
    	if(fingerPrintUtil.isFingerprintAuthAvailable()) {
    		
    		callbackContext.success("ok");
    	
    	}else {
    		 callbackContext.error("Fingerprint Authentication is not available");
    	}
    	
    }
}

