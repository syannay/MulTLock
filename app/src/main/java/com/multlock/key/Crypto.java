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
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

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
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

public class Crypto {
	
    //private static final String CURVE_NAME = "secp160k1";
    //private static final String CURVE_NAME = "prime192v1";
    //private static final String CURVE_NAME = "secp224k1";
    //private static final String CURVE_NAME = "secp256k1";
	
	private static final String CURVE_NAME = "secp256r1"; 

    private static final String TAG = Crypto.class.getSimpleName();

    private static final String PROVIDER = "SC";

    private static final String KEGEN_ALG = "ECDH";

    private static Crypto instance;
    
    private static ECPublicKey blePubKey = null;
    private static ByteArrayBuffer blePubKeyBytes;

    static {
        //Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public KeyFactory kf;
    public KeyPairGenerator kpg;

    static synchronized Crypto getInstance() {
        if (instance == null) {
            instance = new Crypto();
        }

        return instance;
    }

    private Crypto() {
        try {
            kf = KeyFactory.getInstance(KEGEN_ALG, PROVIDER);
            kpg = KeyPairGenerator.getInstance(KEGEN_ALG, PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    static void listAlgorithms(String algFilter) {
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            String providerStr = String.format("%s/%s/%f\n", p.getName(),
                    p.getInfo(), p.getVersion());
            Log.d(TAG, providerStr);
            Set<Service> services = p.getServices();
            List<String> algs = new ArrayList<String>();
            for (Service s : services) {
                boolean match = true;
                if (algFilter != null) {
                    match = s.getAlgorithm().toLowerCase()
                            .contains(algFilter.toLowerCase());
                }

                if (match) {
                    String algStr = String.format("\t%s/%s/%s", s.getType(),
                            s.getAlgorithm(), s.getClassName());
                    algs.add(algStr);
                }
            }

            Collections.sort(algs);
            for (String alg : algs) {
                Log.d(TAG, "\t" + alg);
            }
            Log.d(TAG, "");
        }
    }

    static void listCurves() {
        Log.d(TAG, "Supported named curves:");
        Enumeration<?> names = SECNamedCurves.getNames();
        while (names.hasMoreElements()) {
            Log.d(TAG, "\t" + (String) names.nextElement());
        }
    }

    
    synchronized KeyPair generateKeyPairParams() throws Exception {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "SC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();
        return pair;
    }

    
    synchronized KeyPair generateKeyPairNamedCurve()
            throws Exception {
    	String curveName = CURVE_NAME;
    	
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec(curveName);

        SecureRandom rng = new SecureRandom();
        
        kpg.initialize(ecParamSpec, rng);
        
        return kpg.generateKeyPair();
    }

    static String base64Encode(byte[] b) {
        try {
            return new String(Base64.encode(b), "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    static String hex(byte[] bytes) {
        try {
            return new String(Hex.encode(bytes), "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] base64Decode(String str) {
        return Base64.decode(str);
    }

    static EllipticCurve toCurve(ECParams ecp) {
        ECFieldFp fp = new ECFieldFp(ecp.getP());

        return new EllipticCurve(fp, ecp.getA(), ecp.getB());
    }

    byte[] ecdh(PrivateKey myPrivKey, PublicKey otherPubKey) throws Exception {
        ECPublicKey ecPubKey = (ECPublicKey) otherPubKey;
        Log.d(TAG, "public key Wx: "
                + ecPubKey.getW().getAffineX().toString(16));
        Log.d(TAG, "public key Wy: "
                + ecPubKey.getW().getAffineY().toString(16));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", PROVIDER);
        keyAgreement.init(myPrivKey);
        keyAgreement.doPhase(otherPubKey, true);

        return keyAgreement.generateSecret();
    }

    synchronized PublicKey readPublicKey(String keyStr) throws Exception {
        X509EncodedKeySpec x509ks = new X509EncodedKeySpec(
                Base64.decode(keyStr));
        return kf.generatePublic(x509ks);
    }

    synchronized PrivateKey readPrivateKey(String keyStr) throws Exception {
        PKCS8EncodedKeySpec p8ks = new PKCS8EncodedKeySpec(
                Base64.decode(keyStr));

        return kf.generatePrivate(p8ks);
    }
    
    private KeyPair readKeyPair(SharedPreferences prefs, String key)
            throws Exception {
        String pubKeyStr = prefs.getString(key + "_public", null);
        String privKeyStr = prefs.getString(key + "_private", null);

        if (pubKeyStr == null || privKeyStr == null) {
            return null;
        }

        return readKeyPair(pubKeyStr, privKeyStr);
    }

    synchronized KeyPair readKeyPair(String pubKeyStr, String privKeyStr)
            throws Exception {
        return new KeyPair(readPublicKey(pubKeyStr), readPrivateKey(privKeyStr));
    }
    
    public byte[] sign(Context context, String s) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException
    {
        /*
         * Create a Signature object and initialize it with the private key
         */
    	String str;

        Signature dsa = null;
		try {
			dsa = Signature.getInstance("SHA256withECDSA","SC");
		} catch (NoSuchProviderException e1) {
			e1.printStackTrace();
		}
        
        SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(context);

        KeyPair kpA = null;
		try {
			kpA = readKeyPair(prefs, "kpA");
		} catch (Exception e) {
			e.printStackTrace();
		}
        
        dsa.initSign(kpA.getPrivate());

        if (s == null)
        	str = "This is string to sign";
        else 
        	str = s;
        byte[] strByte = str.getBytes("UTF-8");
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
        Signature ecdsaVerify = null;
        byte [] baText;
        KeyPair kpA = null;
        SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(context);
		try {
			kpA = readKeyPair(prefs, "kpA");
		} catch (Exception e) {
			e.printStackTrace();
		}
        
		//ecdsaVerify = Signature.getInstance("SHA256withECDSA","SC");
		ecdsaVerify = Signature.getInstance("NONEwithECDSA");

        if (publicKey == null)
        	ecdsaVerify.initVerify(kpA.getPublic());
        else 
        	ecdsaVerify.initVerify(publicKey);
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
    
    
    public static byte[] encrypt(SecretKey secret, byte[] buffer, SecureRandom secRand) throws GeneralSecurityException
    {
        /* Encrypt the message. */
    	SecureRandom rng;
    	//String encMethod = "AES/CTR/NoPadding";
    	//String encMethod = "AES/GCM/NoPadding";
    	//String encMethod = "AES/CBC/PKCS5Padding";
    	//String encMethod = "AES/CBC/NoPadding";
    	String encMethod = "AES/CBC/PKCS7Padding";

        Cipher cipher = Cipher.getInstance(encMethod);

        if (secRand == null)
        {
            rng = new SecureRandom();//default uses SHA1PRNG 
        } else {
        	rng = secRand;
        }

        //byte[] ivData = new byte[cipher.getBlockSize()];
        byte[] ivData = {0x11,0x11,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        //rng.nextBytes(ivData);

        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(ivData));        
        byte[] ciphertext = cipher.doFinal(buffer);

        //return Arrays.concatenate(ivData, ciphertext);
        return ciphertext;
    }
    
    public static byte[] decrypt(SecretKey secret, byte[] buffer) throws GeneralSecurityException
    {
        /* Decrypt the message. - use cipher instance created at encrypt */
    	//String encMethod = "AES/CTR/NoPadding";
    	//String encMethod = "AES/GCM/NoPadding";
    	//String encMethod = "AES/CBC/PKCS5Padding";
    	String encMethod = "AES/CBC/NoPadding";

        Cipher cipher = Cipher.getInstance(encMethod);

        int n = cipher.getBlockSize();
        byte[] ivData = Arrays.copyOf(buffer, n);

        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivData));
        byte[] clear = cipher.doFinal(buffer, n, buffer.length - n);

        return clear;
    }
    
    public static void setOtherPublicKey1(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException
    {

    	byte[] pubA = SecPage.g_kpA.getPublic().getEncoded();
    	
    	blePubKeyBytes = new ByteArrayBuffer(pubA.length);
    	
    	blePubKeyBytes.append(pubA, 0, pubA.length - Utils.PUBLIC_KEY_LENGTH);

    	blePubKeyBytes.append(publicKeyBytes, 0, Utils.PUBLIC_KEY_LENGTH);
    	
    	Log.d(TAG, "ble public key = " + publicKeyBytes);
    	
        try {
        	ECPublicKey apub = (ECPublicKey) SecPage.g_kpA.getPublic();
        	ECParameterSpec aspec = apub.getParams();
            //EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            KeyFactory generator = KeyFactory.getInstance("EC");

            //PrivateKey privateKey = generator.generatePrivate(privateKeySpec);

            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            //EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(publicKeyBytes);
            
            blePubKey = (ECPublicKey) generator.generatePublic(publicKeySpec);
            //blePubKey = (ECPublicKey) generator.generatePublic(publicKeySpec);
            //blePubKey = (ECPublicKey) generator.generatePublic((KeySpec)aspec);

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to create KeyPair from provided encoded keys", e);
        }
        Log.d(TAG, "Other Party Public Key Created Successfully");
    }
    
    
    public static PublicKey setOtherPublicKey(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
    	// first generate key pair of your own   
    	ECPublicKey pubKey = (ECPublicKey) SecPage.g_kpA.getPublic();
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
    	blePubKey = (ECPublicKey) keyFactory.generatePublic(otherKeySpec);
    	return blePubKey;
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
    
    
    public static PublicKey getBlePublicKey()
    {
    	return blePubKey;
    }
    
    public static byte[] getBlePubKeyBytes()
    {
    	return blePubKeyBytes.buffer();
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
		md.reset();
    	md.update(in); // Change this to "UTF-16" if needed
    	byte[] digest = md.digest();
    	return digest;
    }

}
