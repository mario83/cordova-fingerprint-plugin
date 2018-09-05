package cordova.plugin.fingerprintplugin;

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

    private void authenticate(CallbackContext callbackContext) {
        callbackContext.success("message");
        // callbackContext.error("Expected one non-empty string argument.");
    }
}

class FingerprintHandler extends FingerprintManager.AuthenticationCallback {
    
    // You should use the CancellationSignal method whenever your app can no longer process user input, for example when your app goes
    // into the background. If you don’t use this method, then other apps will be unable to access the touch sensor, including the lockscreen!//

	private CancellationSignal cancellationSignal;
	private Context context;

	public FingerprintHandler(Context mContext) {
		context = mContext;
	}

	//Implement the startAuth method, which is responsible for starting the fingerprint authentication process//

	public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {

		cancellationSignal = new CancellationSignal();
		// if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
		// 	return;
		// }
		manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
	}

	//onAuthenticationFailed is called when the fingerprint doesn’t match with any of the fingerprints registered on the device//

	@Override
	public void onAuthenticationFailed() {
		Toast.makeText(context, "Authentication failed", Toast.LENGTH_LONG).show();
	}

	//onAuthenticationHelp is called when a non-fatal error has occurred. This method provides additional information about the error,
    //so to provide the user with as much feedback as possible I’m incorporating this information into my toast//
	
    @Override
	public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
		Toast.makeText(context, "Authentication help\n" + helpString, Toast.LENGTH_LONG).show();
	}
    
	//onAuthenticationSucceeded is called when a fingerprint has been successfully matched to one of the fingerprints stored on the user’s device//
    
    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
		Toast.makeText(context, "Success!", Toast.LENGTH_LONG).show();
	}

    //onAuthenticationError is called when a fatal error has occurred. It provides the error code and error message as its parameters//
	
    @Override
	public void onAuthenticationError(int errMsgId, CharSequence errString) {

		//I’m going to display the results of fingerprint authentication as a series of toasts.
        //Here, I’m creating the message that’ll be displayed if an error occurs//

		Toast.makeText(context, "Authentication error\n" + errString, Toast.LENGTH_LONG).show();
	}
}
