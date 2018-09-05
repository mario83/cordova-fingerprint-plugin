package cordova.plugin.fingerprintplugin;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.security.keystore.KeyProperties;
import android.util.Log;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;

public class FingerPrintUtil {

	private CancellationSignal cancellationSignal;

	private FingerprintManager fingerprintManager;
	private Context context;
	public Cipher cipher;

	public FingerPrintUtil(Context context,FingerprintManager fingerprintManager) {
		this.context = context;
		this.fingerprintManager = fingerprintManager;
	}
	
	public boolean isFingerprintAuthAvailable () {
		return fingerprintManager.isHardwareDetected() && fingerprintManager.hasEnrolledFingerprints();
	}
	
	public void authenticate (FingerprintManager.AuthenticationCallback callback) {
		
		if (!this.isFingerprintAuthAvailable()) {
            return;
        }
		
		String transformation = KeyProperties.KEY_ALGORITHM_AES + "/"  + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
		try {
			cipher = Cipher.getInstance(transformation);
			FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
			fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0 , callback, null);
		}catch (NoSuchAlgorithmException e) {
			Log.v("FingerPrintUtil", "NoSuchAlgorithmException");
		}
		
	}
	
	public void cancel() {
		if (cancellationSignal != null) {
			cancellationSignal.cancel();
			cancellationSignal = null;
		}
	}

}