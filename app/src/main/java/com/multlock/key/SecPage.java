package com.multlock.key;

import java.io.File;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.util.ByteArrayBuffer;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Hex;

//import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
//import org.spongycastle.asn1.x9.X9ObjectIdentifiers;
//import org.spongycastle.crypto.generators.KDF2BytesGenerator;
//import org.spongycastle.crypto.generators.KDFCounterBytesGenerator;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.KeyguardManager.KeyguardLock;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class SecPage extends Activity implements OnClickListener {

    private static String TAG = "MTLT_CRYPTO";

    private static String KPA_KEY = "kpA";
    private static String KPB_KEY = "kpB";
    private static byte[] aSecret = null;
    private static byte[] bSecret = null;
    public static KeyPair g_kpA, g_kpB;
    

    private TextView curveNameText;
    private TextView fpSizeText;
    private TextView sharedKeyAText;
    private TextView sharedKeyBText;
    private TextView keyAText;
    private TextView keyBText;
    private SecretKey AES_key;

    private Button listAlgsButton;
    private Button generateKeysButton;
    private Button ecdhButton;
    private Button clearButton;

    private Crypto crypto;
    
    PowerManager pm;
    WakeLock wl;
    KeyguardManager km;
    KeyguardLock kl;
    

    @Override
    public void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.sec_page);

        setProgressBarIndeterminateVisibility(false);

        crypto = Crypto.getInstance();

        curveNameText = (TextView) findViewById(R.id.curve_name_text);
        fpSizeText = (TextView) findViewById(R.id.fp_size_text);
        sharedKeyAText = (TextView) findViewById(R.id.ska_text);
        sharedKeyBText = (TextView) findViewById(R.id.skb_text);
        keyAText = (TextView) findViewById(R.id.pka_text);
        keyBText = (TextView) findViewById(R.id.pkb_text);

        listAlgsButton = (Button) findViewById(R.id.list_algs_button);
        listAlgsButton.setOnClickListener(this);

        generateKeysButton = (Button) findViewById(R.id.generate_keys_button);
        generateKeysButton.setOnClickListener(this);

        ecdhButton = (Button) findViewById(R.id.ecdh_button);
        ecdhButton.setOnClickListener(this);

        clearButton = (Button) findViewById(R.id.clear_button);
        clearButton.setOnClickListener(this);
        
        
        
        pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        km=(KeyguardManager)getSystemService(Context.KEYGUARD_SERVICE);
        kl=km.newKeyguardLock("INFO");
        wl = pm.newWakeLock(PowerManager.FULL_WAKE_LOCK | PowerManager.ACQUIRE_CAUSES_WAKEUP|PowerManager.ON_AFTER_RELEASE, "INFO");
        wl.acquire(); //wake up the screen
        kl.disableKeyguard();// dismiss the keyguard
    }

    @Override
    public void onClick(View v) {
        SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(this);
        if (v.getId() == R.id.list_algs_button) {
            Crypto.listAlgorithms("EC");
            Crypto.listCurves();
        } else if (v.getId() == R.id.generate_keys_button) {
            generateKeys(prefs);
        } else if (v.getId() == R.id.ecdh_button) {
            ecdh(prefs);
        } else if (v.getId() == R.id.clear_button) {
            clear(prefs);
        }
    }

    private void generateKeys(SharedPreferences prefs) {
        final SharedPreferences.Editor prefsEditor = prefs.edit();

        new AsyncTask<Void, Void, Boolean>() {

            ECParams ecp;
            Exception error;

            @Override
            protected void onPreExecute() {
                Toast.makeText(SecPage.this, "Generating ECDH keys...",
                        Toast.LENGTH_SHORT).show();

                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected Boolean doInBackground(Void... arg0) {
                try {
                    ///////KeyPair kpA = crypto.generateKeyPairParams();
                    // saveToFile("kpA_public.der",
                    // kpA.getPublic().getEncoded());
                    // saveToFile("kpA_private.der",
                    // kpA.getPrivate().getEncoded());
                	KeyPair kpA = crypto.generateKeyPairNamedCurve();
                    KeyPair kpB = crypto.generateKeyPairNamedCurve();
                    ////////////KeyPair kpB = crypto.generateKeyPairParams();
                    g_kpA = kpA;
                    g_kpB = kpB;

                    saveKeyPair(prefsEditor, KPA_KEY, kpA);
                    saveKeyPair(prefsEditor, KPB_KEY, kpB);

                    return prefsEditor.commit();
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return false;
                }
            }

            @Override
            protected void onPostExecute(Boolean result) {
                setProgressBarIndeterminateVisibility(false);

                if (result) {
                    //curveNameText.setText("Curve name: " + ecp.name);
                    //fpSizeText.setText("Field size: "
                    //        + Integer.toString(ecp.getField().getFieldSize()));
                    
                    //add keys for comparison
                	int pri_len = g_kpA.getPrivate().getEncoded().length;
                	int pub_len = g_kpA.getPublic().getEncoded().length;
                	PublicKey pubA = g_kpA.getPublic();
                	String s = pubA.toString();
                	Log.d(TAG, "public key length = " + pub_len);
                    keyAText.setText(g_kpA.getPrivate().toString());
                    keyBText.setText(g_kpA.getPublic().toString());
                    Log.d(TAG, "public = " + g_kpA.getPublic().toString());
                    //int pub_len = g_kpA.getPublic().toString().length();
                    //int pri_len = g_kpA.getPrivate().toString().length();
                    curveNameText.setText("public: " + Integer.toString(pub_len) + " private: " + Integer.toString(pri_len));

                    Toast.makeText(SecPage.this,
                            "Successfully generated and saved keys.",
                            Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(
                    		SecPage.this,
                            error == null ? "Error saving keys" : error
                                    .getMessage(), Toast.LENGTH_LONG).show();
                }
            }

        }.execute();
    }

    private void ecdh(final SharedPreferences prefs) {
        new AsyncTask<Void, Void, String[]>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                Toast.makeText(SecPage.this,
                        "Calculating shared ECDH key...", Toast.LENGTH_SHORT)
                        .show();

                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected String[] doInBackground(Void... arg0) {
                try {
                    KeyPair kpA = readKeyPair(prefs, KPA_KEY);
                    if (kpA == null) {
                        throw new IllegalArgumentException(
                                "Key A not found. Generate keys first.");
                    }
                    KeyPair kpB = readKeyPair(prefs, KPB_KEY);
                    if (kpB == null) {
                        throw new IllegalArgumentException(
                                "Key B not found. Generate keys first.");
                    }

//                    aSecret = crypto.ecdh(kpA.getPrivate(),
//                            kpB.getPublic());
                    //byte[] pubKeyBytes = Crypto.getBlePubKeyBytes();
                    //Crypto.setOtherPublicKey(pubKeyBytes);
                    //Crypto.setOtherPublicKey();

                    
                    //test();

                    
                    PublicKey bPub = Crypto.getBlePublicKey();
                    
                    aSecret = crypto.ecdh(kpA.getPrivate(),
                    		bPub);
                    Log.d(TAG, "A secret = " + aSecret);
//                    bSecret = crypto.ecdh(kpB.getPrivate(),
//                            kpA.getPublic());
                    
                    //KeyAgreement keyAgreement = KeyAgreement.getInstance(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId(), "SC");
                    //KeyAgreement keyAgreement = (KeyAgreement)aSecret;
                    //AES_key = keyAgreement.generateSecret(NISTObjectIdentifiers.id_aes256_CBC.getId());
         
                    return new String[] { Crypto.hex(aSecret)};
//                            Crypto.hex(bSecret) };
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return null;
                }
            }

            @Override
            protected void onPostExecute(String[] result) {
                setProgressBarIndeterminateVisibility(false);

                if (result != null && error == null) {
                    sharedKeyAText.setText(result[0]);
                    //sharedKeyBText.setText(result[1]);
                    Log.d(TAG, "A shared secret - " + result[0]);
                } else {
                    Toast.makeText(SecPage.this, error.getMessage(),
                            Toast.LENGTH_LONG).show();
                }
            }

        }.execute();
    }
    
    public void onEncDec(View v) throws Exception
    {
    	String secA = sharedKeyAText.getText().toString();
    	String secB = sharedKeyBText.getText().toString();
    	
    	//byte[] aSecret = secA.getBytes();
    	//byte[] bSecret = secB.getBytes();
    	
        SecretKey secret1 = null;
        SecretKey secret2 = null;
        /*
         * 	using key 0x123400000..... (zero padded)
			encrypt one block with IV=0: in=0x12345678000....., out=5bd560fd2dc00f333616c3b85ae45220
			encrypt two blocka with IV=0: in=12345678123456781234567812345678123456780000000....., out=706bb4b3099b73f34622d54db053098438d55e6be977bd00ec4ea32fed664291
			encrypt one block with IV=0x1111: in=0x12345678000....., out=636a65ea1ab754f5b704f4bfafeb805b
			encrypt two block with IV=0x1111: in=12345678123456781234567812345678123456780000000....., out=9ff3ee19a404a800e7c66f9757de2eafa25bfc4d3d2bf6f6cd9ad305dc61de43
         */
        byte[] ciphertext = null;
        //byte[] message = "Hello, World!".getBytes();
        //byte[] message = {0x12,0x34,0x56,0x78,0,0,0,0,0,0,0,0,0,0,0,0};
        byte[] message = {0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0,0,0,0,0,0,0,0,0,0,0,0};
		byte[] key = {0x12,0x34,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        byte[] clear = null;
        
		try {
			//secret1 = Crypto.createAESKey(aSecret);
			//secret2 = Crypto.createAESKey(bSecret);
			
			secret1 = Crypto.createAESKey(key);
			
//			if (secret1.equals(secret2))
//				Toast.makeText(this, "AES keys are equal", Toast.LENGTH_SHORT).show();
//			else
//				Toast.makeText(this, "AES keys are NOT equal", Toast.LENGTH_SHORT).show();
			
			ciphertext = Crypto.encrypt(secret1, message, null);
			clear = Crypto.decrypt(secret1, ciphertext);
			
	        String s = new  String(clear);//clear.toString();
	        
	        keyAText.setText(new String(message));
	        keyBText.setText(s);
	        
	    	//return;
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        //KDF2BytesGenerator k;
		
    	/*input=0x0000000... zero padded total 32 bytes
    	 * digest = 827cef18adc0160ea8a531fe06e3dc1e22e98def3039d2cbb1da410433195a8b
    	 * 
    	 * input=0x0100000... zero padded total 32 bytes.
			digest = 0x8d074d91f362d3277f1af3a855bb6314629f04d4e72844312d1eb03fb96ca3db
			
			input=0x1234000000... zero padded total 32 bytes.
			digest=82242f99c4ac62e14bc707b6c65d6be243339eedaa13b76175f9bed1f5bd8008
			
			input=1234567812345678123456781234567812345678123456781234567812345678123456780000.... zero padded total 64 bytes.
			digest=026cc7e4494541a563c92ecc2c85ecc20ec3cdeaaa9adec4618c08b0192e0a30
    	 */
		byte[] sha_res;
		byte[] inText = "00000000000000000000000000000000".getBytes();
		sha_res = Crypto.sha256(inText);
		//84e0c0eafaa95a34c293f278ac52e45ce537bab5e752a00e6959a13ae103b65a

		byte[] in0 = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		sha_res = Crypto.sha256(in0);
		byte[] in1 = {0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		sha_res = Crypto.sha256(in1);
		byte[]in2 = {0x12,0x34,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		sha_res = Crypto.sha256(in2);
		byte[]in3 = {0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		sha_res = Crypto.sha256(in3);
    }

    private void clear(SharedPreferences prefs) {
        curveNameText.setText("");
        fpSizeText.setText("");
        sharedKeyAText.setText("");
        sharedKeyBText.setText("");

        SharedPreferences.Editor prefsEditor = prefs.edit();
        prefsEditor.putString(KPA_KEY + "_private", null);
        prefsEditor.putString(KPA_KEY + "_public", null);
        prefsEditor.putString(KPB_KEY + "_private", null);
        prefsEditor.putString(KPB_KEY + "_public", null);

        prefsEditor.commit();

        Toast.makeText(SecPage.this, "Deleted keys.", Toast.LENGTH_LONG)
                .show();
    }
    
    byte[] Signature = {(byte)0x30,(byte)0x46,(byte)0x02,(byte)0x21,(byte)0x00,(byte)0xe5,(byte)0x7e,(byte)0xc8,(byte)0x9b,(byte)0xf5,(byte)0x6c,(byte)0x92,(byte)0x11,(byte)0x38,(byte)0xc1,(byte)0xfc,(byte)0x56,(byte)0x07,(byte)0x8d,(byte)0x92,(byte)0x8d,(byte)0xec,(byte)0x7a,(byte)0xeb,(byte)0xe3,(byte)0x76,(byte)0x9b,(byte)0x8b,(byte)0x51,(byte)0x60,(byte)0x3d,(byte)0x53,(byte)0xaa,(byte)0xa6,(byte)0xf8,(byte)0xc0,(byte)0x65,(byte)0x02,(byte)0x21,(byte)0x00,(byte)0xb3,(byte)0x4f,(byte)0x93,(byte)0xf7,(byte)0x6d,(byte)0x20,(byte)0xdf,(byte)0x55,(byte)0x62,(byte)0x6a,(byte)0xd1,(byte)0xd6,(byte)0xbe,(byte)0x96,(byte)0x6e,(byte)0x1a,(byte)0x3b,(byte)0x4b,(byte)0x3c,(byte)0x6b,(byte)0x19,(byte)0xe0,(byte)0x9c,(byte)0xd1,(byte)0xb2,(byte)0xce,(byte)0x23,(byte)0xe8,(byte)0x8c,(byte)0x10,(byte)0x7f,(byte)0x92};
    final byte[] source = {0};
    
    public void onSign(View v)
    {
    	try {
			Signature = crypto.sign(v.getContext(), new String(source));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return;
    }
    
    public void onVerify(View v)
    {
    	try {
    		PublicKey key = null;
    		//byte[] remoteKey = {(byte)0x04,(byte)0x68,(byte)0x05,(byte)0x28,(byte)0x10,(byte)0x62,(byte)0x17,(byte)0x28,(byte)0xc7,(byte)0xd7,(byte)0xcd,(byte)0x9d,(byte)0xcc,(byte)0x14,(byte)0xe6,(byte)0x04,(byte)0x16,(byte)0xad,(byte)0x08,(byte)0x95,(byte)0xc6,(byte)0x19,(byte)0xa1,(byte)0x41,(byte)0xa4,(byte)0xd6,(byte)0xe0,(byte)0x46,(byte)0x1d,(byte)0x13,(byte)0xb5,(byte)0x0f,(byte)0x40,(byte)0x32,(byte)0xfa,(byte)0x5c,(byte)0xd5,(byte)0x6b,(byte)0x1e,(byte)0xd9,(byte)0x1e,(byte)0xd6,(byte)0x3d,(byte)0x3e,(byte)0xd5,(byte)0x12,(byte)0x0d,(byte)0x41,(byte)0x1f,(byte)0x27,(byte)0x21,(byte)0xc7,(byte)0xf3,(byte)0x63,(byte)0xc1,(byte)0x08,(byte)0xe3,(byte)0x8e,(byte)0x69,(byte)0xb8,(byte)0x65,(byte)0xe8,(byte)0xb8,(byte)0xe7,(byte)0x68};
    		byte[] remoteKey = {(byte)0x68,(byte)0x05,(byte)0x28,(byte)0x10,(byte)0x62,(byte)0x17,(byte)0x28,(byte)0xc7,(byte)0xd7,(byte)0xcd,(byte)0x9d,(byte)0xcc,(byte)0x14,(byte)0xe6,(byte)0x04,(byte)0x16,(byte)0xad,(byte)0x08,(byte)0x95,(byte)0xc6,(byte)0x19,(byte)0xa1,(byte)0x41,(byte)0xa4,(byte)0xd6,(byte)0xe0,(byte)0x46,(byte)0x1d,(byte)0x13,(byte)0xb5,(byte)0x0f,(byte)0x40,(byte)0x32,(byte)0xfa,(byte)0x5c,(byte)0xd5,(byte)0x6b,(byte)0x1e,(byte)0xd9,(byte)0x1e,(byte)0xd6,(byte)0x3d,(byte)0x3e,(byte)0xd5,(byte)0x12,(byte)0x0d,(byte)0x41,(byte)0x1f,(byte)0x27,(byte)0x21,(byte)0xc7,(byte)0xf3,(byte)0x63,(byte)0xc1,(byte)0x08,(byte)0xe3,(byte)0x8e,(byte)0x69,(byte)0xb8,(byte)0x65,(byte)0xe8,(byte)0xb8,(byte)0xe7,(byte)0x68};
    		try {
				key = Crypto.setOtherPublicKey(remoteKey);
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			boolean b = crypto.verify(v.getContext(), key, source, Signature);
			if (b)
				Toast.makeText(v.getContext(), "Verification SUCCEEDED", Toast.LENGTH_SHORT).show();
			else
				Toast.makeText(v.getContext(), "Verification FAILED", Toast.LENGTH_SHORT).show();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return;
    }

    private void saveKeyPair(SharedPreferences.Editor prefsEditor, String key,
            KeyPair kp) {
        String pubStr = Crypto.base64Encode(kp.getPublic().getEncoded());
        String privStr = Crypto.base64Encode(kp.getPrivate().getEncoded());

        prefsEditor.putString(key + "_public", pubStr);
        prefsEditor.putString(key + "_private", privStr);
    }

    @SuppressWarnings("unused")
    private void saveToFile(String filename, byte[] bytes) throws Exception {
        File file = new File(Environment.getExternalStorageDirectory(),
                filename);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.flush();
        fos.close();
    }

    private KeyPair readKeyPair(SharedPreferences prefs, String key)
            throws Exception {
        String pubKeyStr = prefs.getString(key + "_public", null);
        String privKeyStr = prefs.getString(key + "_private", null);

        if (pubKeyStr == null || privKeyStr == null) {
            return null;
        }

        return crypto.readKeyPair(pubKeyStr, privKeyStr);
    }
    
    private void test() throws NoSuchAlgorithmException, InvalidKeySpecException
    {
    	// first generate key pair of your own   
//    	KeyPairGenerator kpgen = KeyPairGenerator.getInstance("EC");
//    	ECGenParameterSpec genspec = new ECGenParameterSpec("secp256r1");
//    	kpgen.initialize(genspec);
//    	KeyPair generateKeyPair = kpgen.generateKeyPair();

    	// get the parameters and key size
//    	ECPublicKey pubKey = (ECPublicKey) generateKeyPair.getPublic();
    	ECPublicKey pubKey = (ECPublicKey) g_kpA.getPublic();
    	ECParameterSpec params = pubKey.getParams();
    	int keySizeBytes = params.getOrder().bitLength() / Byte.SIZE;

    	// get the other party 64 bytes
    	//byte [] otherPub = crypto.getBlePubKeyBytes();
    	byte[] otherPub = hexStringToByteArray("ac2bdd28fce5c7b181b34f098b0934742281246ed907a5f646940c1edcb724e7c7358356aebea810322a8e324cc77f376df4cabd754110ad41ec178c0a6b8e5f");
    	ByteArrayBuffer xBytes = new ByteArrayBuffer(33);
    	ByteArrayBuffer yBytes = new ByteArrayBuffer(33);
    	
    	byte[] zero = {(byte)0x00};
    	xBytes.append(zero, 0, 1);
    	xBytes.append(otherPub, 0, 32);
    	yBytes.append(zero, 0, 1);
    	yBytes.append(otherPub, 32, 32);
    	
    	
    	// generate the public key point    
    	int offset = 0;
    	BigInteger x = new BigInteger(xBytes.buffer());
    	//x = new BigInteger(1, Arrays.copyOfRange(pubKey, offset, offset + keySizeBytes));
    	offset += keySizeBytes;
    	BigInteger y = new BigInteger(yBytes.buffer());
    	
    	//y = new BigInteger(1, Arrays.copyOfRange(pubKey, offset, offset + keySizeBytes));
    	ECPoint w  = new ECPoint(x, y);

    	// generate the key of the other side
    	ECPublicKeySpec otherKeySpec = new ECPublicKeySpec(w  , params);
    	KeyFactory keyFactory = KeyFactory.getInstance("EC");
    	PublicKey otherKey = keyFactory.generatePublic(otherKeySpec);

    	// perform key agreement    
//    	KeyAgreement ka = KeyAgreement.getInstance("ECDH");
//    	ka.init(generateKeyPair.getPrivate());
//    	ka.doPhase(otherKey, true);
//    	byte[] secret = ka.generateSecret();
//    	System.out.println(Hex.toHexString(secret));
//    	You can use the Bouncy Castle provider for Brainpool curves:

//    	Security.addProvider(new BouncyCastleProvider());
//    	KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
//    	ECGenParameterSpec genspec = new ECGenParameterSpec("BrainpoolP256R1");
//    	And to convert your public key do this (half of the answer provided):

//    	int keyLengthBytes = pubKey.getParams().getOrder().bitLength() / Byte.SIZE;
//    	byte[] publicKeyEncoded = new byte[2 * keyLengthBytes];
//
//    	int offset = 0;
//
//    	{
//    	    BigInteger x = pubKey.getW().getAffineX();
//    	    byte[] xba = x.toByteArray();
//    	    if (xba.length > keyLengthBytes + 1
//    	            || xba.length == keyLengthBytes + 1 && xba[0] != 0) {
//    	        throw new IllegalStateException("X coordinate of EC public key has wrong size");
//    	    }
//
//    	    if (xba.length == keyLengthBytes + 1) {
//    	        System.arraycopy(xba, 1, publicKeyEncoded, offset, keyLengthBytes);
//    	    } else {
//    	        System.arraycopy(xba, 0, publicKeyEncoded, offset + keyLengthBytes - xba.length, xba.length);
//    	    }
//    	}
//
//    	System.out.println("Hex: " + Hex.toHexString(publicKeyEncoded));
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}

