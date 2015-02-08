
package com.multlock.key;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.http.util.ByteArrayBuffer;
import org.spongycastle.util.Arrays;


import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;


import android.os.AsyncTask;


public class SecUtils {
	
    private static KeyFactory kf;
    private static KeyPairGenerator kpg;
    //private static KeyPair keyPair;
    
    private static Context context;
    
    private static final String PROVIDER = "SC";

    private static final String KEGEN_ALG = "ECDH";

	private static PublicKey publicKey = null;
	private static PrivateKey privateKey = null;
	private static PublicKey remotePublic = null;
	private static PublicKey remoteTempPublic = null;
	private static SecretKey lastAES = null;
	private static byte[] blastAES = null;
	private static byte[] lastRandom = null;
	private static byte[] ecdhResult = null;
	private static byte[] sharedSecret = null;
	private static byte lasthandshakeId = (byte)-1;
	private static ByteArrayBuffer lastIV = new ByteArrayBuffer(SecUtils.getIvLength());
	private static ByteArrayBuffer lastIV2 = new ByteArrayBuffer(SecUtils.getIvLength());
    private static boolean lastIV2Initiated = false;
	private static String STR_PUBLIC_BYTES = "PUBLIC_KEY_BYTES";
	private static String STR_REMOTE_PUBLIC_BYTES = "REMOTE_PUBLIC_KEY_BYTES";
	private static String STR_TEMP_REMOTE_PUBLIC_BYTES = "TEMP_REMOTE_PUBLIC_KEY_BYTES";
	private static String STR_PRIVATE_BYTES = "PRIVATE_KEY_BYTES";
	private static String TAG = "MTLT";
	private static enum publicType {ENUM_LOCAL, ENUM_REMOTE, ENUM_TEMP_REMOTE};
	//private static String encMethod = "AES/CTR/NoPadding";
	//private static String encMethod = "AES/GCM/NoPadding";
	//private static String encMethod = "AES/CBC/PKCS5Padding";
	//private static String encMethod = "AES/CBC/NoPadding";
	private static String encMethod = "AES/CBC/PKCS7Padding";
	
	private static Crypto crypto = null;
	
	private static Context getContext()
	{
		return context;
	}
	
	public static void setContext(Context context)
	{
		SecUtils.context = context;
	}
	
	private static PublicKey getPublicInstance(byte[] publicKeyBytes)
	{
		try {
			KeyFactory generator = KeyFactory.getInstance("EC");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);            
            publicKey = (ECPublicKey) generator.generatePublic(publicKeySpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return publicKey;
	}
	
	private static PrivateKey getPrivateInstance(byte[] privateKeyBytes)
	{
		try {
			KeyFactory generator = KeyFactory.getInstance("EC");
            EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(privateKeyBytes);            
            privateKey = (PrivateKey) generator.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return privateKey;
	}
	
	private static PublicKey getPublicKey(publicType type)
	{
		PublicKey pk = null;
		String name = null;
		
		switch (type) {
		case ENUM_LOCAL:
			pk = publicKey;
			name = SecUtils.STR_PUBLIC_BYTES;
			break;
		case ENUM_REMOTE:
			pk = remotePublic;
			name = SecUtils.STR_REMOTE_PUBLIC_BYTES;
			break;
		case ENUM_TEMP_REMOTE:
			pk = remoteTempPublic;
			name = SecUtils.STR_TEMP_REMOTE_PUBLIC_BYTES;
			break;
		}
		if (pk != null)
			return pk;
		//read data from mobile
		if (SecUtils.getContext() == null)
			return null;
		SharedPreferences pref = getContext().getSharedPreferences(TAG, Context.MODE_PRIVATE);
		String tmp = pref.getString(name, null);
		if (tmp == null) 
			return null;
		
		byte[] publicKeyBytes = Base64.decode(tmp, Base64.DEFAULT);
		
		if (publicKeyBytes == null)
			return null;
		pk = SecUtils.getPublicInstance(publicKeyBytes);
		switch (type) {
		case ENUM_LOCAL:
			publicKey = pk;
			break;
		case ENUM_REMOTE:
			remotePublic = pk;
			break;
		case ENUM_TEMP_REMOTE:
			remoteTempPublic = pk;
			break;
		}
		return pk;
	}
	
	private static void setPublicKey(publicType type, PublicKey key)
	{
		String name = null;
		
		byte[] encoded = key.getEncoded();
		//store the data
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		
		ByteArrayBuffer buffer = new ByteArrayBuffer(Utils.PUBLIC_KEY_LENGTH);
		buffer.append(encoded, encoded.length - Utils.PUBLIC_KEY_LENGTH, Utils.PUBLIC_KEY_LENGTH);

		String s = Base64.encodeToString(buffer.buffer(), Base64.DEFAULT);
		
		switch (type) {
		case ENUM_LOCAL:
			publicKey = key;
			name = SecUtils.STR_PUBLIC_BYTES;
			break;
		case ENUM_REMOTE:
			remotePublic = key;
			name = SecUtils.STR_REMOTE_PUBLIC_BYTES;
			break;
		case ENUM_TEMP_REMOTE:
			remoteTempPublic = key;
			name = SecUtils.STR_TEMP_REMOTE_PUBLIC_BYTES;
			break;
		}
		
		editor.putString(name, s);		
		// Commit the edits!
		editor.commit();
	}
	
	public static PrivateKey getPrivateKey()
	{
		PrivateKey tmpPrivateKey = null;
		
		if (privateKey != null)
			return privateKey;
		//read data from mobile
		if (SecUtils.getContext() == null)
			return null;
		SharedPreferences pref = getContext().getSharedPreferences(TAG, Context.MODE_PRIVATE);
		String tmp = pref.getString(STR_PRIVATE_BYTES, null);
		if (tmp == null) 
			return null;
		byte[] privateKeyBytes = Base64.decode(tmp, Base64.DEFAULT);
		if (privateKeyBytes == null)
			return null;
		//tmpPrivateKey = SecUtils.getPrivateInstance(privateKeyBytes);
		
        KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("EC");
	        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
	        tmpPrivateKey = keyFactory.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	    
		return tmpPrivateKey;
	}
	
	
	public static void setPrivateKey(PrivateKey privateKey)
	{

		byte[] encoded = privateKey.getEncoded();
		//store the data
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();

		String s = Base64.encodeToString(encoded, Base64.DEFAULT);
		
		editor.putString(STR_PRIVATE_BYTES, s);		
		// Commit the edits!
		editor.commit();
	}
 
	
	public static PublicKey getLocalPublicKey()
	{
		return SecUtils.getPublicKey(publicType.ENUM_LOCAL);
	}
	
	public static void setLocalPublicKey(PublicKey pk)
	{
		SecUtils.setPublicKey(publicType.ENUM_LOCAL, pk);
	}
	
	public static PublicKey getRemoteECDSAPublicKey()
	{
		return SecUtils.getPublicKey(publicType.ENUM_REMOTE);
	}
	
	private static void setRemoteECDSAPublicKey(PublicKey pk)
	{
		SecUtils.setPublicKey(publicType.ENUM_REMOTE, pk);
	}
	
	public static void setRemoteECDSAPublicKey(byte[] pk)
	{
		PublicKey key = null;
		try {
			key = SecUtils.Bytes2PublicKey(pk);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SecUtils.setRemoteECDSAPublicKey(key);
	}
	
	public static void setRemoteAESPublicKey(byte[] pk)
	{
		PublicKey key = null;
		try {
			key = SecUtils.Bytes2PublicKey(pk);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SecUtils.setRemoteAESPublic(key);
	}
	
	public static PublicKey getRemoteAESPublic()
	{
		return SecUtils.getPublicKey(publicType.ENUM_TEMP_REMOTE);
	}
	
	public static void setRemoteAESPublic(PublicKey pk)
	{
		SecUtils.setPublicKey(publicType.ENUM_TEMP_REMOTE, pk);
	}

	public static SecretKey getLastAES()
	{
		if (lastAES != null)
			return lastAES;
		//*** SECURITY - persistence can be removed and be called directly
		byte[] bytes = SecUtils.getByteArrayPersist(Utils.STR_AES_KEY);
		lastAES = SecUtils.getKeyFromBytes(bytes);
		blastAES = lastAES.getEncoded();
		return lastAES;
	}
	
	private static SecretKey getFixAES()
	{
		byte[] key = {0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03};
		return SecUtils.getKeyFromBytes(key);
	}
	
	public static void setLastAES(SecretKey key)
	{
		lastAES = key;
		blastAES = key.getEncoded();
		//*** SECURITY - persistence can be removed and called directly to store the data
		SecUtils.setByteArrayPersist(Utils.STR_AES_KEY, blastAES);
	}
	
	public static byte[] getLastAESBytes()
	{
		if (blastAES != null)
			return blastAES;
		//*** SECURITY - persistence can be removed
		blastAES = SecUtils.getByteArrayPersist(Utils.STR_AES_KEY);
		lastAES = SecUtils.getKeyFromBytes(blastAES);
		return blastAES;
	}
	
	public static void setLastAESBytes(byte[] key)
	{
		blastAES = key;
		//*** SECURITY - persistence can be removed and called directly
		SecUtils.setByteArrayPersist(Utils.STR_AES_KEY, key);
		SecUtils.lastAES = SecUtils.getKeyFromBytes(key);
	}
	
	public static byte[] getLastRandom()
	{
		return lastRandom;
	}
	
	public static void setLastRandom(byte[] random)
	{
		lastRandom = random;
	}
 
	public static byte[] getEcdhResult()
	{
		return ecdhResult;
	}
	
	public static void setEcdhResult(byte[] code)
	{
		ecdhResult = code;
	}
	
	public static byte[] getSharedSecret()
	{
		return sharedSecret;
	}
	
	public static void setSharedSecret(byte[] code)
	{
		sharedSecret = code;
	}
	
	private static final String CURVE_NAME = "secp256r1"; 
	
    private static synchronized KeyPair generateKeyPairNamedCurve()
            throws Exception {
    	String curveName = CURVE_NAME;
    	
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec(curveName);

        SecureRandom rng = new SecureRandom();
        
        kpg.initialize(ecParamSpec, rng);
        
        return kpg.generateKeyPair();
    }
	
    public static void generateKeys() {

        new AsyncTask<Void, Void, Boolean>() {
            Exception error;


            @Override
            protected Boolean doInBackground(Void... arg0) {
                try {
 
                	KeyPair kpA = SecUtils.generateKeyPairNamedCurve();

                    setLocalPublicKey(kpA.getPublic());
                    return true;
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return false;
                }
            }

        }.execute();
    }
    
    public static byte[] syncECDH()
    {
        try {
        	PrivateKey privateKey = SecUtils.getPrivateKey();
            if (privateKey == null) {
                throw new IllegalArgumentException(
                        "Local key not found. Generate keys first.");
            }
            PublicKey remotePublic = SecUtils.getRemoteAESPublic();
            if (remotePublic == null) {
                throw new IllegalArgumentException(
                        "Remote Public Key not found. Get keys first.");
            }
            
            byte[] aSecret = ecdh(privateKey, remotePublic);
            SecUtils.setSharedSecret(aSecret);
            Log.d(TAG, "A secret = " + aSecret);
       
 
            return aSecret;
//                    Crypto.hex(bSecret) };
        } catch (Exception e) {
            return null;
        }
    }
    
    public static void ecdh() {
        new AsyncTask<Void, Void, String[]>() {

            Exception error;


            @Override
            protected String[] doInBackground(Void... arg0) {
                try {
                	PrivateKey privateKey = SecUtils.getPrivateKey();
                    if (privateKey == null) {
                        throw new IllegalArgumentException(
                                "Local key not found. Generate keys first.");
                    }
                    PublicKey remotePublic = SecUtils.getRemoteAESPublic();
                    if (remotePublic == null) {
                        throw new IllegalArgumentException(
                                "Remote Public Key not found. Get keys first.");
                    }
                    
                    byte[] aSecret = ecdh(privateKey, remotePublic);
                    SecUtils.setSharedSecret(aSecret);
                    Log.d(TAG, "A secret = " + aSecret);
               
         
                    return new String[] { Crypto.hex(aSecret)};
//                            Crypto.hex(bSecret) };
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return null;
                }
            }

        }.execute();
    }
    
    private static byte[] ecdh(PrivateKey myPrivKey, PublicKey otherPubKey) throws Exception {

//        Log.d(TAG, "public key Wx: "
//                + ecPubKey.getW().getAffineX().toString(16));
//        Log.d(TAG, "public key Wy: "
//                + ecPubKey.getW().getAffineY().toString(16));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", PROVIDER);
        keyAgreement.init(myPrivKey);
        keyAgreement.doPhase(otherPubKey, true);

        return keyAgreement.generateSecret();
    }

    public static byte[] sha256(byte[] in)
    {
    	MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	//String text = "This is some text";

    	md.update(in); // Change this to "UTF-16" if needed
    	byte[] digest = md.digest();
    	return digest;
    }
    
    public static byte[] sha1(byte[] in)
    {
    	MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	//String text = "This is some text";

    	md.update(in); // Change this to "UTF-16" if needed
    	byte[] digest = md.digest();
    	return digest;
    }
    
    private static String convertToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (byte b : data) {
            int halfbyte = (b >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                buf.append((0 <= halfbyte) && (halfbyte <= 9) ? (char) ('0' + halfbyte) : (char) ('a' + (halfbyte - 10)));
                halfbyte = b & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    public static String SHA1(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(text.getBytes("iso-8859-1"), 0, text.length());
        byte[] sha1hash = md.digest();
        return convertToHex(sha1hash);
    }
    
    public static PublicKey Bytes2PublicKey(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
    	// first generate key pair of your own   
    	//ECPublicKey pubKey = (ECPublicKey) SecPage.g_kpA.getPublic();
    	ECPublicKey pubKey = (ECPublicKey) SecUtils.getPublicKey(SecUtils.publicType.ENUM_LOCAL);
    	ECParameterSpec params = pubKey.getParams();
    	int keySizeBytes = params.getOrder().bitLength() / Byte.SIZE;

    	// get the other party 64 bytes
    	//byte [] otherPub = crypto.getBlePubKeyBytes();
    	byte[] otherPub = publicKeyBytes;
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
    	offset += keySizeBytes;
    	BigInteger y = new BigInteger(yBytes.buffer());
    	
    	ECPoint w  = new ECPoint(x, y);

    	// generate the key of the other side
    	ECPublicKeySpec otherKeySpec = new ECPublicKeySpec(w  , params);
    	KeyFactory keyFactory = KeyFactory.getInstance("EC");
    	PublicKey blePubKey = (ECPublicKey) keyFactory.generatePublic(otherKeySpec);
    	return blePubKey;
    }
    
    public byte[] sign(Context context, byte[] s) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException
    {
        /*
         * Create a Signature object and initialize it with the private key
         */
    	byte[] strByte;

        Signature dsa = Signature.getInstance("NONEwithECDSA");

        PrivateKey privateKey = SecUtils.getPrivateKey();
        
        dsa.initSign(privateKey);

        if (s == null)
        	strByte = "This is string to sign".getBytes();
        else 
        	strByte = s;
        dsa.update(strByte);
       

        /*
         * Now that all the data to be signed has been read in, generate a
         * signature for it
         */

        byte[] realSig = dsa.sign();
        return realSig;
        //(new BigInteger(1, realSig).toString(16));
    }
    
    public boolean verify(Context context, PublicKey publicKey, byte[] baSource, byte[] baSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature ecdsaVerify;
        byte [] baText;

        PublicKey pk = SecUtils.getPublicKey(SecUtils.publicType.ENUM_REMOTE);
        
        ecdsaVerify = Signature.getInstance("NONEwithECDSA");
        
        ecdsaVerify.initVerify(pk);

        if (baSource == null)
        	baText = "This is string to sign".getBytes();
        else 
        	baText = baSource;
        
        ecdsaVerify.update(baText);
        boolean result = ecdsaVerify.verify(baSignature);
        return result;
    }
    
    public static SecretKey createAESKey(byte[] aSecret) throws InvalidKeySpecException, NoSuchAlgorithmException
    {     
        SecretKeySpec secret = new SecretKeySpec(aSecret, "AES");
        return secret;
    }
    
    private static Cipher cipher = null;
    
    public static byte[] encrypt(SecretKey secret, byte[] buffer, SecureRandom secRand) throws GeneralSecurityException
    {
        /* Encrypt the message. */
    	SecureRandom rng;

    	if (cipher == null)
    		cipher = Cipher.getInstance(encMethod);

//        if (secRand == null)
//        {
//            rng = new SecureRandom();//default uses SHA1PRNG 
//        } else {
//        	rng = secRand;
//        }

        byte[] ivData = SecUtils.getNextIv();
        
//        byte[] ivData = new byte[cipher.getBlockSize()];
//        rng.nextBytes(ivData);
        
        if (secret == null)
        	secret = SecUtils.getLastAES();
        
        if (secret == null)
        	return null;

        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(ivData));
        byte[] ciphertext = cipher.doFinal(buffer);
        
        byte[] tmp = new byte[1];
        tmp[0] = ivData[0];

        return Arrays.concatenate(tmp, ciphertext);
        //return ciphertext;
    }
    
    public static byte[] encrypt2(SecretKey secret, byte[] buffer, SecureRandom secRand) throws GeneralSecurityException
    {
        /* Encrypt the message. */
    	SecureRandom rng;

    	if (cipher == null)
    		cipher = Cipher.getInstance(encMethod);

        byte[] ivData = SecUtils.getNextIv2();
        
        if (secret == null)
        	secret = SecUtils.getFixAES();
        
        if (secret == null)
        	return null;

        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(ivData));
        byte[] ciphertext = cipher.doFinal(buffer);
        
        byte[] tmp = new byte[1];
        tmp[0] = ivData[0];

        return Arrays.concatenate(tmp, ciphertext);
        //return ciphertext;
    }


    public static byte[] decrypt(SecretKey secret, byte[] buffer, byte[] iv) throws GeneralSecurityException
    {
        /* Decrypt the message. - use cipher instance created at encrypt */
    	
        if (secret == null)
        	secret = SecUtils.getLastAES();
        
        if (secret == null)
        	return null;

    	if (cipher == null)
    		cipher = Cipher.getInstance(encMethod);

        int n = cipher.getBlockSize();
        
        byte[] tmp = new byte[1];
        tmp[0] = buffer[0];
        
        byte[] lastIv = SecUtils.getLastIv();
        byte[] ivData = SecUtils.getManipulatedIv(lastIv, tmp);
        
        
//        if (iv == null)
//        	ivData = Arrays.copyOf(buffer, n);
//        else
//        	ivData = iv;

        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivData));
        //byte[] clear = cipher.doFinal(buffer, 0, buffer.length);
        byte[] clear = cipher.doFinal(buffer, 1, buffer.length - 1);

        return clear;
    }
    
    public static byte[] decrypt2(SecretKey secret, byte[] buffer, byte[] iv) throws GeneralSecurityException
    {
        /* Decrypt the message. - use cipher instance created at encrypt */
    	
        if (secret == null)
        	secret = SecUtils.getFixAES();
        
        if (secret == null)
        	return null;

    	if (cipher == null)
    		cipher = Cipher.getInstance(encMethod);

        int n = cipher.getBlockSize();
        
        byte[] tmp = new byte[1];
        tmp[0] = buffer[0];
        
        byte[] lastIv = SecUtils.getLastIv2();
        byte[] ivData = SecUtils.getManipulatedIv(lastIv, tmp);
        
        
//        if (iv == null)
//        	ivData = Arrays.copyOf(buffer, n);
//        else
//        	ivData = iv;

        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivData));
        //byte[] clear = cipher.doFinal(buffer, 0, buffer.length);
        byte[] clear = cipher.doFinal(buffer, 1, buffer.length - 1);

        return clear;
    }
    
    public static boolean secInit(Context mainContext)
    {
    	SecUtils.setContext(mainContext);
    	crypto = Crypto.getInstance();
//            kf = KeyFactory.getInstance(KEGEN_ALG, PROVIDER);
//            kpg = KeyPairGenerator.getInstance(KEGEN_ALG, PROVIDER);
    	kpg = crypto.kpg;
    	kf = crypto.kf;

    	KeyPair kpA = null;
    	PrivateKey prk = SecUtils.getPrivateKey();
    	PublicKey puk = SecUtils.getPublicKey(SecUtils.publicType.ENUM_LOCAL);
    	if (puk == null || prk == null) {
			try {
				kpA = SecUtils.generateKeyPairNamedCurve();
				privateKey = kpA.getPrivate();
				publicKey = kpA.getPublic();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			SecUtils.setLocalPublicKey(kpA.getPublic());
            SecUtils.setPrivateKey(kpA.getPrivate());
    	}
    	return true;
    }
    
    public static void initSecurityParamsForSession(byte[] receivedIv, byte[] remoteAESPublic, byte[] remoteECDSAPublic)
    {
//		SecUtils.setLastRandom(receivedRandom);
    	SecUtils.setNextIv(receivedIv);
		SecUtils.setRemoteAESPublicKey(remoteAESPublic);
	
		byte[] secret = SecUtils.syncECDH();
		//SecretKey secret = SecUtils.createAESKey(SecUtils.getSharedSecret());
		byte[] aes256 = SecUtils.sha256(secret);
		ByteArrayBuffer aes128 = new ByteArrayBuffer(16);
		aes128.append(aes256, 0, 16);
		SecUtils.setLastAESBytes(aes128.buffer());
		SecretKey key = getKeyFromBytes(aes128.buffer());
		SecUtils.setLastAES(key);
		SecUtils.setRemoteECDSAPublicKey(remoteECDSAPublic);
    }
    
    private static SecretKey getKeyFromBytes(byte[] bytes) {
		SecretKey key = new SecretKeySpec(bytes, 0, bytes.length, "AES");
		return key;
    }
    

	public static byte[] manipulateRandom(byte[] random) {
//		byte[] newRandom = new byte[Utils.RANDOM_KEY_LENGTH];
//		newRandom = Arrays.copyOf(random, Utils.RANDOM_KEY_LENGTH);

		byte[] newRandom = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		return newRandom;
	}
	
	private static byte[] getNextIv()
	{
		byte[] lastIv = SecUtils.getLastIv();
		byte[] b = SecUtils.getRndIv();
		byte[] next = getManipulatedIv(lastIv, b);

		SecUtils.setNextIv(next);
		return next;
	}
	
	private static byte[] getNextIv2()
	{
		byte[] lastIv = SecUtils.getLastIv2();
		byte[] b = SecUtils.getRndIv();
		byte[] next = getManipulatedIv(lastIv, b);

		SecUtils.setNextIv2(next);
		return next;
	}
	
	private static byte[] getManipulatedIv(byte[] iv, byte[] rnd) {
		ByteArrayBuffer buffer = new ByteArrayBuffer(SecUtils.getIvLength());
		buffer.append(rnd, 0, rnd.length);
		buffer.append(iv, rnd.length, iv.length - rnd.length);
		return buffer.buffer();
	}
	
	private static byte[] getLastIv()
	{
		return lastIV.buffer();
	}
	
	private static byte[] getLastIv2()
	{
		return lastIV2.buffer();
	}
	
	public static void setNextIv(byte[] iv)
	{
		lastIV.clear();
		lastIV.append(iv, 0, SecUtils.getIvLength());
	}
	
	public static void setNextIv2(byte[] iv)
	{
		lastIV2.clear();
		lastIV2.append(iv, 0, SecUtils.getIvLength());
        lastIV2Initiated = true;
	}

    public static boolean isLastIV2Initiated()
    {
        return lastIV2Initiated;
    }
	
	public static int getIvLength()
	{
		return Utils.IV_LENGTH;
	}
	
	public static byte[] getByteArrayPersist(String name)
	{		
		//read data from mobile
		SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		String tmp = pref.getString(name, null);
		if (tmp == null) 
			return null;
		byte[] bytes = Base64.decode(tmp, Base64.DEFAULT);
		if (bytes == null)
			return null;
		//tmpPrivateKey = SecUtils.getPrivateInstance(privateKeyBytes);
	    
		return bytes;
	}
	
	
	public static void setByteArrayPersist(String name, byte[] bytes)
	{
		//store the data
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();

		String s = Base64.encodeToString(bytes, Base64.DEFAULT);
		
		editor.putString(name, s);		
		// Commit the edits!
		editor.commit();
	}
	
	private static byte[] getRndIv() {
		SecureRandom ranGen = new SecureRandom();
		byte[] rByte = new byte[1];
		ranGen.nextBytes(rByte);
		return rByte;
	}
	
	public static byte getLastHandshakeId() {
		return SecUtils.lasthandshakeId;
	}
	
	public static void setLastHandshakeId(byte id) {
		SecUtils.lasthandshakeId = id;
		Log.d(TAG, "handshake id set = " + id);
	}
	
	public static void initSecuredComm(String lockName)
	{
		byte id = SecUtils.getPersistentHandshakeId(lockName);
		if (id == (byte) -1) {
			//perform ECDH and handshake
		}
	}
	
	public static byte getPersistentHandshakeId(String name) {
		
		//read data from mobile
		SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		int id = pref.getInt(Utils.STR_BLE_ASSOCIATION_ID + name, -1);
		if (id != -1)
			SecUtils.restorePersistentForLock(name);
		return (byte)id;
	}
	
	public static void setPersistentHandshakeId(String name, byte id) {
		//store the data
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		
		editor.putInt(Utils.STR_BLE_ASSOCIATION_ID + name, (int)id);		
		// Commit the edits!
		editor.commit();
	}
	
	public static void storePersistentForLock(String currentDeviceName)
	{
		byte[] aes = SecUtils.getLastAESBytes();
		SecUtils.setByteArrayPersist(currentDeviceName + "-aes", aes);
		
		byte[] ecDsa = SecUtils.getRemoteECDSAPublicKey().getEncoded();
		SecUtils.setByteArrayPersist(currentDeviceName + "-ecdsa", ecDsa);
	}
	
	public static void restorePersistentForLock(String currentDeviceName)
	{
		byte[] aes = SecUtils.getByteArrayPersist(currentDeviceName + "-aes");
		SecUtils.setLastAESBytes(aes);
		
		byte[] ecDsa = SecUtils.getByteArrayPersist(currentDeviceName + "-ecdsa");
		SecUtils.setRemoteECDSAPublicKey(ecDsa);
	}

}
