package cordova.plugin.fingerprintplugin;

import android.Manifest;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.annotation.TargetApi;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.lang.Exception;

/**
 * This class echoes a string called from JavaScript.
 */
@TargetApi(23)
public class FingerprintPlugin extends CordovaPlugin {

    public static final String TAG = "FingerprintAuth";
    
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String SHARED_PREFS_NAME = "FingerSPref";

	/**
     * Alias for our key in the Android Key Store
     */
    private final static String CLIENT_ID = "CordovaFingerprintPlugin";
    // public static String _packageName;
    public static KeyStore _keyStore;
    public static KeyGenerator _keyGenerator;
    public static Cipher _cipher;
    public static CallbackContext _callbackContext;
    public static PluginResult _pluginResult;
	
	// Plugin response codes and messages
    private static final String OS = "OS";
    private static final String ANDROID = "Android";
    private static final String ERROR_CODE = "ErrorCode";
    private static final String ERROR_MESSAGE = "ErrorMessage";
    private static final String NO_SECRET_KEY_CODE = "-5";
    private static final String NO_SECRET_MESSAGE = "Secret Key not set.";
    private static final String NO_HARDWARE_CODE = "-6";
    private static final String NO_HARDWARE_MESSAGE = "Biometry is not available on this device.";
    private static final String NO_FINGERPRINT_ENROLLED_CODE = "-7";
    private static final String NO_FINGERPRINT_ENROLLED_MESSAGE =
            "No fingers are enrolled with Touch ID.";

    // Plugin Javascript actions
    private static final String SAVE = "save";
    private static final String VERIFY = "verify";
    private static final String IS_AVAILABLE = "isAvailable";
    private static final String DELETE = "delete";
    private static final String HAS = "has";

	 /**
     * Used to encrypt token
     */
    private static String _keyID;
    // KeyguardManager mKeyguardManager;
    // FingerprintAuthenticationDialogFragment mFragment;
    // private FingerprintManager mFingerPrintManager;
    private int _currentMode;
    // private String mLangCode = "en_US";
	
	/**
     * String to encrypt
     */
    private String _toEncrypt;
	
	public Context applicationContext;
	private FingerprintManager _fingerPrintManager;

    private CordovaInterface _cordova;
    
    private CancellationSignal _cancellationSignal;
	private boolean _selfCancelled;
	
	public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(TAG, "initialize: FingerprintAuth");

		_cordova = cordova;

		try {
            _keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            _keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            _cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                    + "/"
                    + KeyProperties.BLOCK_MODE_CBC
                    + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }

        applicationContext = cordova.getActivity().getApplicationContext();
        _fingerPrintManager = applicationContext.getSystemService(FingerprintManager.class);
	}
	
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    	
		_callbackContext = callbackContext;

    	Log.v(TAG, "execute: action "+action);

		if (action.equals(IS_AVAILABLE)) {
            if (isHardwareDetected()) {
                if (hasEnrolledFingerprints()) {
                    _pluginResult = new PluginResult(PluginResult.Status.OK);
                } else {
                    String errorMessage =
                            createErrorMessage(NO_FINGERPRINT_ENROLLED_CODE, NO_FINGERPRINT_ENROLLED_MESSAGE);
                    _pluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                }
            } else {
                String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
                _pluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            }

            callbackContext.sendPluginResult(_pluginResult);
            return true;
        } else if (action.equals(SAVE)) {
            final String key = args.getString(0);
            final String password = args.getString(1);

            if (isFingerprintAuthAvailable()) {
                SecretKey secretKey = getSecretKey();

                if (secretKey == null) {
                    if (createKey()) {
                        getSecretKey();
                    }
                }
                _keyID = key;
                _toEncrypt = password;
                initCipher(Cipher.ENCRYPT_MODE);
                startListening(new FingerprintManager.CryptoObject(_cipher),_callbackContext);
                
            } else {
                String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
                _pluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            }
            return true;
        } else if (action.equals(VERIFY)) {
            final String key = args.getString(0);
            if (isHardwareDetected()) {
                if (hasEnrolledFingerprints()) {
                    SecretKey secretKey = getSecretKey();
                    if (secretKey != null) {
                        _keyID = key;
                        initCipher(Cipher.DECRYPT_MODE);
                        startListening(new FingerprintManager.CryptoObject(_cipher),_callbackContext);
                        _pluginResult.setKeepCallback(true);
                    } else {
                        String errorMessage = createErrorMessage(NO_SECRET_KEY_CODE, NO_SECRET_MESSAGE);
                        _pluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                        _callbackContext.sendPluginResult(_pluginResult);
                    }
                } else {
                    String errorMessage =
                            createErrorMessage(NO_FINGERPRINT_ENROLLED_CODE, NO_FINGERPRINT_ENROLLED_MESSAGE);
                    _pluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                    _callbackContext.sendPluginResult(_pluginResult);
                }
            } else {
                String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
                _pluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                _callbackContext.sendPluginResult(_pluginResult);
            }
            return true;
        } else if (action.equals(HAS)) { //if has key
            String key = args.getString(0);

            SharedPreferences sharedPref = _cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
            String enc = sharedPref.getString("fing" + key, "");

            if (!enc.equals("")) {
                _pluginResult = new PluginResult(PluginResult.Status.OK);
            } else {
                _pluginResult = new PluginResult(PluginResult.Status.ERROR);
            }

            _callbackContext.sendPluginResult(_pluginResult);
            return true;
        } else if (action.equals(DELETE)) { //delete key
            final String key = args.getString(0);
            SharedPreferences sharedPref = _cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.remove("fing" + key);
            editor.remove("fing_iv" + key);
            boolean removed = editor.commit();
            if (removed) {
                _pluginResult = new PluginResult(PluginResult.Status.OK);
            } else {
                _pluginResult = new PluginResult(PluginResult.Status.ERROR);
            }
            _callbackContext.sendPluginResult(_pluginResult);
            return true;
        }

        return false;
    }

	private boolean isFingerprintAuthAvailable() {
        return isHardwareDetected() && hasEnrolledFingerprints();
    }

	private boolean isHardwareDetected() {
        if (_cordova.getActivity().checkSelfPermission(Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return false;
        }

        return _fingerPrintManager.isHardwareDetected();
    }

	private boolean hasEnrolledFingerprints() {
        if (_cordova.getActivity().checkSelfPermission(Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return false;
        }

        return _fingerPrintManager.hasEnrolledFingerprints();
    }

	private SecretKey getSecretKey() {
        String errorMessage = "";
        String getSecretKeyExceptionErrorPrefix = "Failed to get SecretKey from KeyStore: ";
        SecretKey key = null;
        try {
           _keyStore.load(null);
            key = (SecretKey)_keyStore.getKey(CLIENT_ID, null);
        } catch (KeyStoreException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "KeyStoreException";
        } catch (CertificateException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "CertificateException";
        } catch (UnrecoverableKeyException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableKeyException";
        } catch (IOException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "IOException";
        } catch (NoSuchAlgorithmException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "NoSuchAlgorithmException";
        }
        if (key == null) {
            Log.e(TAG, errorMessage);
        }
        return key;
    }

	/**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    public static boolean createKey() {
        String errorMessage = "";
        String createKeyExceptionErrorPrefix = "Failed to create key: ";
        boolean isKeyCreated = false;
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            _keyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            _keyGenerator.init(new KeyGenParameterSpec.Builder(CLIENT_ID,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(
                    KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            _keyGenerator.generateKey();
            isKeyCreated = true;
        } catch (NoSuchAlgorithmException e) {
            errorMessage = createKeyExceptionErrorPrefix + "NoSuchAlgorithmException";
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = createKeyExceptionErrorPrefix + "InvalidAlgorithmParameterException";
        } catch (CertificateException e) {
            errorMessage = createKeyExceptionErrorPrefix + "CertificateException";
        } catch (IOException e) {
            errorMessage = createKeyExceptionErrorPrefix + "IOException";
        }
        if (!isKeyCreated) {
            Log.e(TAG, errorMessage);
            setPluginResultError(errorMessage);
        }
        return isKeyCreated;
    }

	public static boolean setPluginResultError(String errorMessage) {
        _callbackContext.error(errorMessage);
        _pluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the
     * {@link #createKey(boolean setUserAuthenticationRequired)}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher(int mode) {
        _currentMode = mode;
        boolean initCipher = false;
        String errorMessage = "";
        String initCipherExceptionErrorPrefix = "Failed to init Cipher: ";
        try {
            SecretKey key = getSecretKey();

            if (mode == Cipher.ENCRYPT_MODE) {
                SecureRandom r = new SecureRandom();
                byte[] ivBytes = new byte[16];
                r.nextBytes(ivBytes);

                _cipher.init(mode, key);
            } else {
                SharedPreferences sharedPref = _cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                byte[] ivBytes =
                        Base64.decode(sharedPref.getString("fing_iv" +_keyID, ""), Base64.DEFAULT);

                _cipher.init(mode, key, new IvParameterSpec(ivBytes));
            }

            initCipher = true;
        } catch (KeyPermanentlyInvalidatedException e) {
            Log.e(TAG, e.getMessage(),e);
            removePermanentlyInvalidatedKey();
            errorMessage = "KeyPermanentlyInvalidatedException";
            setPluginResultError(errorMessage);
        } catch (InvalidKeyException e) {
            Log.e(TAG, e.getMessage(),e);
            errorMessage = initCipherExceptionErrorPrefix + "InvalidKeyException";
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, e.getMessage(),e);
            errorMessage = initCipherExceptionErrorPrefix + "InvalidAlgorithmParameterException";
        }
        if (!initCipher) {
            Log.e(TAG, errorMessage);
        }
        return initCipher;
    }

    private void removePermanentlyInvalidatedKey() {
        try {
            _keyStore.deleteEntry(CLIENT_ID);
            Log.i(TAG, "Permanently invalidated key was removed.");
        } catch (KeyStoreException e) {
            Log.e(TAG, e.getMessage());
        }
    }

	private String createErrorMessage(final String errorCode, final String errorMessage) {
        JSONObject resultJson = new JSONObject();
        try {
            resultJson.put(OS, ANDROID);
            resultJson.put(ERROR_CODE, errorCode);
            resultJson.put(ERROR_MESSAGE, errorMessage);
            return resultJson.toString();
        } catch (JSONException e) {
            Log.e(TAG, e.getMessage());
        }
        return "";
    }
    
    public void onAuthenticated() {
        String result = "";
        String errorMessage = "";
        try {

             // If the user has authenticated with fingerprint, verify that using cryptography and
            // then return the encrypted token
            SharedPreferences sharedPref = _cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
            if (_currentMode == Cipher.DECRYPT_MODE) {
                byte[] enc = Base64.decode(sharedPref.getString("fing" + _keyID, ""), Base64.DEFAULT);

                byte[] decrypted = _cipher.doFinal(enc);
                result = new String(decrypted);
            } else if (_currentMode == Cipher.ENCRYPT_MODE) {
                //encript string with key after authenticate with fingerprint
                SharedPreferences.Editor editor = sharedPref.edit();

                byte[] enc = _cipher.doFinal(_toEncrypt.getBytes());
                editor.putString("fing" + _keyID, Base64.encodeToString(enc, Base64.DEFAULT));
                editor.putString("fing_iv" + _keyID,
                        Base64.encodeToString(_cipher.getIV(), Base64.DEFAULT));

                editor.commit();
                _toEncrypt = "";
                result = "success";
            }
        } catch (BadPaddingException e) {
            errorMessage = "Failed to encrypt the data with the generated key:"
                    + " BadPaddingException:  "
                    + e.getMessage();
            Log.e(TAG, errorMessage);
        } catch (IllegalBlockSizeException e) {
            errorMessage = "Failed to encrypt the data with the generated key: "
                    + "IllegalBlockSizeException: "
                    + e.getMessage();
            Log.e(TAG, errorMessage);
        }

        if (!result.equals("")) {
            _pluginResult = new PluginResult(PluginResult.Status.OK, result);
            _pluginResult.setKeepCallback(false);
        } else {
            _pluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            _pluginResult.setKeepCallback(false);
        }
        _callbackContext.sendPluginResult(_pluginResult);
    }

    public void startListening(FingerprintManager.CryptoObject cryptoObject, CallbackContext callbackContext) {
        if (!isFingerprintAuthAvailable()) {
            return;
        }
        _cancellationSignal = new CancellationSignal();
        _selfCancelled = false;
        _fingerPrintManager
                .authenticate(cryptoObject, _cancellationSignal, 0, new FingerprintManager.AuthenticationCallback () {
                    @Override
                    public void onAuthenticationError(int errMsgId, CharSequence errString) {
                        callbackContext.error(errString.toString());
                    }
    
                    @Override
                    public void onAuthenticationFailed() {
                        callbackContext.error("onAuthenticationFailed");
                    }
    
                    @Override
                    public void onAuthenticationHelp(int helpMsgId,CharSequence helpString) {
                        callbackContext.error(helpString.toString());
                    }
    
                    @Override
                    public void onAuthenticationSucceeded(
                            FingerprintManager.AuthenticationResult result) {
    
                            onAuthenticated();
                        // callbackContext.success("onAuthenticationSucceeded");
                    }
                }, null);
    }

    public void stopListening() {
        if (_cancellationSignal != null) {
            _selfCancelled = true;
            _cancellationSignal.cancel();
            _cancellationSignal = null;
        }
    }
}
