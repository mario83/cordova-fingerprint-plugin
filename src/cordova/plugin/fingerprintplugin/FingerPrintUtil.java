package cordova.plugin.fingerprintplugin;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;

public class FingerPrintUtil {

	private CancellationSignal cancellationSignal;

	private FingerprintManager fingerprintManager;
	private Context context;
	
	public FingerPrintUtil(Context context,FingerprintManager fingerprintManager) {
		this.context = context;
		this.fingerprintManager = fingerprintManager;
	}
	
	public boolean isFingerprintAuthAvailable () {
		return fingerprintManager.isHardwareDetected() && fingerprintManager.hasEnrolledFingerprints();
	}
	
	public boolean authenticate () {
		
		if (!this.isFingerprintAuthAvailable()) {
            return false;
        }
		
//		fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0 , this, null);
		
//		fingerprintManager.CryptoObject
//		cancellationSignal = new CancellationSignal();
//		authenticate(FingerprintManager.CryptoObject crypto, cancellationSignal, int flags, FingerprintManager.AuthenticationCallback callback, Handler handler)
	}
	
	public void cancel() {
		if (cancellationSignal != null) {
			cancellationSignal.cancel();
			cancellationSignal = null;
		}
	}

}