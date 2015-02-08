
package com.multlock.key;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;



import org.apache.http.util.ByteArrayBuffer;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Environment;
import android.telephony.TelephonyManager;
import android.util.Base64;
import android.util.Log;

public class Utils {
	
    public static final int KNOWN_DEVICES_SCAN_INTERVAL = 2500;
    
	//temporary ENUM the commands
    public static final byte ENUM_CMD_SEND_PUBLIC_KEY = 10;
    public static final byte ENUM_CMD_HANDSHAKE1 = 11;
    public static final byte ENUM_CMD_SET_OWNER = 12;
    public static final byte ENUM_CMD_SET_OWNER_RESPONSE = 13;
    public static final byte ENUM_CMD_KDF = 14;
    public static final byte ENUM_CMD_CREATE_NEW_KEY = 15;
    public static final byte ENUM_CMD_GET_NEW_KEY = 16;
    public static final byte ENUM_CMD_UNLOCK = 17;
    public static final byte ENUM_CMD_LOCK = 18;
    public static final byte ENUM_CMD_GET_NEW_KEY_RESPONSE = 19;
    public static final byte ENUM_CMD_KDF_RESPONSE = 20;
    public static final byte ENUM_CMD_UNLOCK_RESPONSE = 21;
    public static final byte ENUM_CMD_LOCK_RESPONSE = 22;
    public static final byte ENUM_CMD_CREATE_NEW_KEY_RESPONSE = 23;
    public static final byte ENUM_CMD_OP_CONFIG = 24;
    public static final byte ENUM_CMD_OP_STATUS = 25;
    public static final byte ENUM_CMD_GET_KEYS = 26;
    public static final byte ENUM_CMD_GET_KEYS_RESPONSE = 27;
    public static final byte ENUM_CMD_REVOKE_KEY = 28;
    public static final byte ENUM_CMD_DISABLE_KEY = 29;
    public static final byte ENUM_CMD_GET_DEVICE_CONFIG = 30;
    public static final byte ENUM_CMD_GET_DEVICE_CONFIG_RESPONSE = 31;
    public static final byte ENUM_CMD_ENABLE_KEY	= 32;
    public static final byte ENUM_CMD_GET_PENDING_KEYS = 33;
    public static final byte ENUM_CMD_GET_PENDING_KEYS_RESPONSE = 34;
    public static final byte ENUM_CMD_REVOKE_PENDING_KEY = 35;
    public static final byte ENUM_CMD_SET_ADMIN_CODE = 36;
    public static final byte ENUM_CMD_VERIFY_ADMIN_CODE = 37;
    public static final byte ENUM_CMD_RECOVER_OWNER = 38;
    public static final byte ENUM_CMD_RECOVER_OWNER_RESPONSE = 39;
    public static final byte ENUM_CMD_SET_OWNER_ACK = 40;
    public static final byte ENUM_CMD_GET_NEW_KEY_ACK = 41;
    public static final byte ENUM_CMD_GET_DEVICE_CONFIG_RESPONSE_ACK = 42;
    public static final byte ENUM_CMD_GET_COMMUNICATION_VERSION = 43;
    public static final byte ENUM_CMD_GET_COMMUNICATION_VERSION_RESPONSE = 44;
    public static final byte ENUM_CMD_GET_DEVICE_INFO = 45;
    public static final byte ENUM_CMD_GET_DEVICE_INFO_RESPONSE = 46;
    public static final byte ENUM_CMD_OP_DEVICE_CONFIG = 47;
    public static final byte ENUM_CMD_OTA_UPDATE = 48;
    public static final byte ENUM_CMD_GET_ERRORS = 49;
    public static final byte ENUM_CMD_GET_ERRORS_RESPONSE = 50;
    
    public static final byte ENUM_CMD_GET_FOTA_COMM_VER_RESPONSE = (byte)151;
    public static final byte ENUM_CMD_DOWNLOAD_PARAMS_REQUEST = (byte)152;
    public static final byte ENUM_CMD_DOWNLOAD_PARAMS_RESPONSE = (byte)153;
    public static final byte ENUM_CMD_DOWNLOAD_CHUNK_16 = (byte)154;
    public static final byte ENUM_CMD_DOWNLOAD_CHUNK_8 = (byte)155;
    public static final byte ENUM_CMD_DOWNLOAD_CHUNK_STATUS = (byte)156;
    public static final byte ENUM_CMD_DOWNLOAD_COMPLETE = (byte)157;
    public static final byte ENUM_CMD_DOWNLOAD_COMPLETE_RESPONSE = (byte)158;
    public static final byte ENUM_CMD_INSTALL_REQUEST = (byte)159;
    public static final byte ENUM_CMD_INSTALL_STATUS = (byte)160;
    public static final byte ENUM_CMD_DOWNLOAD_PARAMS_CHANGE_REQUEST = (byte)162;
    public static final byte ENUM_CMD_GET_IV = (byte)163;
    public static final byte ENUM_CMD_GET_IV_RESPONSE = (byte)164;
    
    public static final byte ENUM_CMD_OP_SUCCESS_IMP = 100;
    public static final byte ENUM_CMD_OP_SUCCESS_EXP = 101;
    public static final byte ENUM_CMD_OP_ERROR = 102;
	
    public static final byte ENUM_CMD_GENERAL_ENCRYPTED = 120;
    public static final byte ENUM_CMD_GENERAL_PLAIN = 121;
    
    public static final byte ENUM_CMD_RESEND_CHUNK = (byte)200;
    
    public static final byte ENUM_EMULATE_LOCK_EXISTENCE = 10;
    public static final byte ENUM_EMULATE_ERROR = 11;
    
    public static final int ENUM_CMD_CONNECT = 1000;

	
	
	
    public static final String STR_KEY = "MTLT_KEY";
    public static final String STR_PUBLIC_KEY = "PUBLIC_KEY";
    public static final String STR_ECDSA_PUBLIC_KEY = "TEMP_PUBLIC_KEY";
    public static final String STR_RANDOM_KEY = "RANDOM_KEY";
    public static final String STR_APP_ID = "APP_ID";
    public static final String STR_USER_ID = "USER_ID";
    public static final String STR_BLE_SIGNATURE = "BLE_SIGNATURE";
    public static final String STR_PREV_ADMIN_CODE = "PREV_ADMIN_CODE";
    public static final String STR_ADMIN_CODE = "ADMIN_CODE";
    public static final String STR_MODE = "MODE";
    public static final String STR_BLE_ASSOCIATION_ID = "BLE_ID";
    public static final String STR_BLE_EKEY = "LEKEY";
    public static final String STR_LOCK_NAME = "LOCK_NAME";
    public static final String STR_KEY_NAME = "KEY_NAME";
    public static final String STR_COMMAND = "COMMAND";
    public static final String STR_NEW_USER_PIN = "USER_PIN";
    public static final String STR_ERROR_CODE_TYPE = "ERROR_CODE";
    public static final String STR_ERROR_CODE_DETAIL = "ERROR_CODE";
    public static final String STR_CONFIG_ID = "CONFIG_ID";
    public static final String STR_CONFIG_VALUE = "CONFIG_VALUE";
    public static final String STR_CONFIG_VALUE_LENGTH = "CONFIG_VALUE_LENGTH";
    public static final String STR_STATUS_TYPE_ID = "STATUS_TYPE_ID";
    public static final String STR_STATUS_VALUE_LENGTH = "STATUS_VALUE_LENGTH";
    public static final String STR_STATUS_VALUE = "STATUS_VALUE";
    public static final String STR_DEVICE_INDEX = "DEVICE_INDEX";
    public static final String STR_KEY_LIST = "KEY_LIST";
    public static final String STR_DEVICE_CONFIG_MUTE = "DEVICE_MUTE";
    public static final String STR_DEVICE_CONFIG_AUTO_LOCK = "DEVICE_AUTO_LOCK";
    public static final String STR_DEVICE_CONFIG_ALLOW_REMOTE = "DEVICE_ALLOW_REMOTE";
    public static final String STR_DEVICE_CONFIG_REQUIRE_PIN = "DEVICE_REQUIRE_PIN";
    public static final String STR_DEVICE_STATE_LOCK_LOCKED = "LOCK_IS_LOCKED";
    public static final String STR_DEVICE_STATE_DOOR_CLOSED = "DOOR_IS_CLOSED";
    public static final String STR_DEVICE_STATE_LOCK_CHARGING = "LOCK_IS_CHARGING";
    public static final String STR_DEVICE_STATE_BATTERY_STATE = "BATTERY_STATE";
    public static final String STR_DEVICE_STATE_BATTERY_PERCENTAGE = "BATTERY_PERCENTAGE";
    public static final String STR_SERVICE_ON = "SERVICE_ON";
    public static final String STR_APP_PROTECTED = "APP_PROTECTED";
    public static final String STR_APP_PROTECTION_CODE = "APP_PROTECTION_CODE";
    public static final String STR_KEYS = "LOCK_KEYS";
    public static final String STR_EXPIRATION = "GET_KEY_EXPIRATION";
    public static final String STR_ROLE = "USER_ROLE";
    public static final String STR_PROVIDER_ID = "PROVIDER_ID";
    public static final String STR_IV = "IV";
    public static final String STR_AES_KEY = "AES_KEY";
    public static final String STR_COMMUNICATION_VERSION = "COMM_VERSION";
    public static final String STR_DEVICE_INFO= "DEVICE_INFO";
    public static final String STR_DEVICE_ID_LENGTH = "DEVICE_ID_LENGTH";
    public static final String STR_DEVICE_ID = "DEVICE_ID";
    public static final String STR_DEVICE_MODEL_LENGTH = "DEVICE_MODEL_LENGTH";
    public static final String STR_DEVICE_MODEL = "DEVICE_MODEL";
    public static final String STR_DEVICE_CODE_VERSION_LENGTH = "DEVICE_CODE_VERSION_LENGTH";
    public static final String STR_DEVICE_CODE_VERSION = "DEVICE_CODE_VERSION";
    public static final String STR_IGNORE_VALUE = "IGNORE_VALUE";
    public static final String STR_DEVICE_STATUS = "DEVICE_STATUS";
    public static final String STR_OWNER_UNLOCK_CODE = "OWNER_UNLOCK_CODE";
    public static final String STR_OTA_UPDATE_DATA = "OTA_UPDATE_DATA";
    public static final String STR_DP_LENGTH = "DP_LENGTH";
    public static final String STR_DP_FLAGS = "DP_FLAGS";
    public static final String STR_PREFERRED_START_ADDRESS = "PREFERRED_START_ADDRESS";
    public static final String STR_PREFERRED_CHUNK_SIZE = "PREFERRED_CHUNK_SIZE";
    public static final String STR_CHUNK_NUM = "CHUNK_NUM";
    public static final String STR_DOWNLOAD_COMPLETE_STATUS = "DOWNLOAD_COMPLETE_STATUS";
    public static final String STR_DP_CONTENT = "DP_CONTENT";
    public static final String STR_INSTALL_STATUS = "INSTALL_STATUS";
    public static final String STR_DOWNLOAD_CHUNK_STATUS = "DOWNLOAD_CHUNK_STATUS";
    public static final String STR_DEVICE_UPDATE_STATUS = "DEVICE_UPDATE_STATUS";
    public static final String STR_GET_ERRORS_COMMAND = "GET_ERRORS_COMMAND";
    public static final String STR_GET_ERRORS_RESPONSE_DATA = "GET_ERRORS_RESPONSE_DATA";
    

    
    private static final int ENUM_STR_LOCK_NAME = 1;
    private static final int ENUM_STR_KEY_NAME = 2;
    private static final int ENUM_STR_USER_NAME = 3;
    private static final int ENUM_STR_EKEY = 4;
    private static final int ENUM_STR_ROLE = 5;
    private static final int ENUM_STR_OPEN_MODE = 6;
    private static final int ENUM_STR_LOCK_ID = 7;

    private static final String STR_LOCK_LIST = "LOCK_LIST";
    
    public static final int PUBLIC_KEY_LENGTH = 64;
    public static final int ECDSA_PUBLIC_KEY_LENGTH = 64;
    public static final int RANDOM_KEY_LENGTH = 32;
    public static final int APP_ID_LENGTH = 16;
    public static final int USER_ID_LENGTH = 16;
    public static final int BLE_SIGNATURE_LENGTH = 72;
    public static final int PREV_ADMIN_CODE_LENGTH = 6;
    public static final int ADMIN_CODE_LENGTH = 6;
    public static final int MODE_LENGTH = 1;
    public static final int BLE_ASSOCIATION_ID_LENGTH = 1;
    public static final int BLE_EKEY_LENGTH = 32;
    public static final int LOCK_NAME_LENGTH = 16;
    public static final int KEY_NAME_LENGTH = 16;
    public static final int COMMAND_LENGTH = 1;
    public static final int NEW_USER_PIN_LENGTH = 6;
    public static final int ERROR_CODE_TYPE_LENGTH = 1;
    public static final int ERROR_CODE_DETAIL_LENGTH = 2;
    public static final int CONFIG_ID_LENGTH = 1;
    public static final int CONFIG_VALUE_LENGTH = 1;
    public static final int TYPE_ID_LENGTH = 1;
    public static final int STATUS_VALUE_LENGTH = 1;
    public static final int KEY_LIST_LENGTH_LENGTH = 1;
    public static final int DEVICE_CONFIG_MUTE_LENGTH = 1;
    public static final int DEVICE_CONFIG_AUTO_LOCK_LENGTH = 1;
    public static final int DEVICE_CONFIG_ALLOW_REMOTE_LENGTH = 1;
    public static final int DEVICE_CONFIG_REQUIRE_PIN_LENGTH = 1;  
    public static final int EXPIRATION_LENGTH = 1;
    public static final int ROLE_LENGTH = 1;
    public static final int PROVIDER_ID_LENGTH = 1;
    public static final int IV_LENGTH = 16;
    public static final int COMMUNICATION_VERSION_LENGTH = 1;
    public static final int DEVICE_INFO_LENGTH = 1;
    public static final int DEVICE_ID_LENGTH_LENGTH = 1;
    public static final int DEVICE_MODEL_LENGTH_LENGTH = 1;
    public static final int DEVICE_CODE_VERSION_LENGTH_LENGTH = 1;
    public static final int PREV_VALUE_IS_LENGTH = 100000;
    public static final int DEVICE_STATUS_LENGTH = 1;
    public static final int OWNER_UNLOCK_CODE_LENGTH = 4;
    public static final int DP_LENGTH_LENGTH = 4;
    public static final int DP_FLAGS_LENGTH = 4;
    public static final int PREFERRED_START_ADDRESS_LENGTH = 4;
    public static final int PREFERRED_CHUNK_SIZE_LENGTH = 2;
    public static final int CHUNK_NUM_LENGTH_16 = 2;
    public static final int CHUNK_NUM_LENGTH_8 = 1;
    public static final int DOWNLOAD_COMPLETE_STATUS_LENGTH = 1;
    public static final int DP_CONTENT_LENGTH = 1;
    public static final int INSTALL_STATUS_LENGTH = 1;
    public static final int DOWNLOAD_CHUNK_STATUS_LENGTH = 1;
    public static final int DEVICE_UPDATE_STATUS_LENGTH = 4;
    public static final int GET_ERRORS_DATA_LENGTH_LENGTH = 1;
    public static final int GET_ERRORS_COMMAND_LENGTH = 8;
    
    
    
    public static final byte LOCK_STATE_UNINITIALIZED = 0;
    public static final byte LOCK_STATE_INITIALIZED = 1;
    public static final byte LOCK_STATE_INITIALIZED_WITH_KEYS_PENDING = 2;
    
    public static final int ADVERTISE_DATA_LOCATION = 5;
    public static final int ADVERTISE_DEVICE_STATUS_LOCATION = 6;
    public static final int ADVERTISE_BATTERY_STATUS_LOCATION = 7;
    
    
    public static final int EXPLICIT_SUCCESS_COMMAND_LOCATION = 0;
    
    //error codes   
    public static final int ERROR_CATEGORY_BadInput	= 1;
    public static final int ERROR_CATEGORY_InsufficientResources = 2;
    public static final int ERROR_CATEGORY_CommunicationError = 3;
    public static final int ERROR_CATEGORY_InternalError = 4;
    public static final int ERROR_CATEGORY_AppLegitimateError = 5;

    
    public static final int ERROR_DETAIL_WrongPublicKeyLength = 1;
    public static final int ERROR_DETAIL_CantSendPublicKey	= 2;
    public static final int ERROR_DETAIL_UnsupportedCommand = 3;
    public static final int ERROR_DETAIL_UnsupportedCmdInBuff = 4;
    public static final int ERROR_DETAIL_WrongAppIDRandLength = 5;
    public static final int ERROR_DETAIL_WrongSetOwnerLength = 6;
    public static final int ERROR_DETAIL_WrongOwnerCode = 7;
    public static final int ERROR_DETAIL_CantSendSetOwnerResp = 8;
    public static final int ERROR_DETAIL_WrongKDF = 9;
    public static final int ERROR_DETAIL_WrongCreateKeyLength = 10;
    public static final int ERROR_DETAIL_CantSendCreateKeyResp = 11;
    public static final int ERROR_DETAIL_WrongGetKeyLength = 12;
    public static final int ERROR_DETAIL_WrongUserID = 13;
    public static final int ERROR_DETAIL_WrongPIN = 14;
    public static final int ERROR_DETAIL_KeyGenerationError = 15;
    public static final int ERROR_DETAIL_WrongUnlockLength = 16;
    public static final int ERROR_DETAIL_WrongEKey = 17;
    public static final int ERROR_DETAIL_WrongConfigLength = 18;
    public static final int ERROR_DETAIL_WrongCfgParamLength = 19;
    public static final int ERROR_DETAIL_UnsupportedConfig = 20;
    public static final int ERROR_DETAIL_CantSendConfigResp = 21;
    public static final int ERROR_DETAIL_CantSendOpSuccess = 22;
    public static final int ERROR_DETAIL_LockBusy = 23; //	Locking or Unlocking operation is already in place. New request aborted.
    public static final int ERROR_DETAIL_LockMainCommError = 24;	
    public static final int ERROR_DETAIL_LockError = 25; //	Error of unsuccessful locking or unlocking operation
    public static final int ERROR_DETAIL_LockInqEarlyTermination = 26;  //	Inquiry from Main MCU if there is command has terminated before command from phone appeared or completed
    public static final int ERROR_DETAIL_LockTimeout = 27;  //	Timeout in trying to pass the lock/unlock command to Main MCU for execution
    public static final int ERROR_DETAIL_CommandSuspended = 28; // code was wrong for several times and action blocked for n minutes



    
    private static final String TAG = "MultLock-Keys";
    private static final String LOCK_DELIMITER = "###";
    private static ArrayList<KeyData> keyList = null;
    private static ArrayList<KeyData1> keyList1 = null;
    
    public static final int BATTERY_STATE_LOW = 0;
    public static final int BATTERY_STATE_MEDIUM = 1;
    public static final int BATTERY_STATE_HIGH = 2;
    
    public static final int ENUM_ROLE_USER = 0;
    public static final int ENUM_ROLE_ADMIN = 1;
    public static final int ENUM_ROLE_OWNER = 2;
    
    public static class KeyData {
    	//private byte[] eKey = new byte[Utils.BLE_EKEY_LENGTH];
    	//private byte[] lockName = new byte[Utils.LOCK_NAME_LENGTH];
    	//private byte[] keyName = new byte[Utils.KEY_NAME_LENGTH];
    	private static final int fullSize = Utils.BLE_EKEY_LENGTH+Utils.LOCK_NAME_LENGTH+Utils.KEY_NAME_LENGTH+Utils.USER_ID_LENGTH;
    	private ByteArrayBuffer data = new ByteArrayBuffer(this.fullSize);
    	
    	public static int getKeyDataSize() { return fullSize; }
    	
       	KeyData()
    	{
    		//data will be set by setters
    	}
    	
    	KeyData(byte[] eKey, byte[] lockName, byte[] keyName, byte[] userId)
    	{
    		//need to add - lock id, isAdmin, key name, open_mode (ENUM - Manual - Auto - Notification - NOT Parking {will be in another list})
    		data.append(eKey, 0, eKey.length);
    		data.append(lockName, 0, lockName.length);
    		data.append(keyName, 0, keyName.length);
    		data.append(userId, 0, userId.length);
    	}
    	
    	public byte[] getEKey()
    	{
    		int start = 0;
    		int end = start + Utils.BLE_EKEY_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    	
    	public byte[] getUser()
    	{
    		int start = Utils.BLE_EKEY_LENGTH + Utils.LOCK_NAME_LENGTH + Utils.KEY_NAME_LENGTH;
    		int end = start + Utils.USER_ID_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    	
    	public byte[] getLockName()
    	{
    		int start = Utils.BLE_EKEY_LENGTH;
    		int end = start + Utils.LOCK_NAME_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    	
    	public byte[] getKeyName()
    	{
    		int start = Utils.BLE_EKEY_LENGTH + Utils.LOCK_NAME_LENGTH;
    		int end = start + Utils.KEY_NAME_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    }
    
    public static class KeyData1 {
    	//private byte[] eKey = new byte[Utils.BLE_EKEY_LENGTH];
    	//private byte[] lockName = new byte[Utils.LOCK_NAME_LENGTH];
    	//private byte[] keyName = new byte[Utils.KEY_NAME_LENGTH];
    	private static final int fullSize = Utils.BLE_EKEY_LENGTH+Utils.LOCK_NAME_LENGTH+Utils.KEY_NAME_LENGTH+Utils.USER_ID_LENGTH;
    	private ByteArrayBuffer data = new ByteArrayBuffer(this.fullSize);
    	
    	public static int getKeyDataSize() { return fullSize; }
    	
       	KeyData1()
    	{
    		//data will be set by setters
    	}
    	
    	KeyData1(byte[] eKey, byte[] lockName, byte[] keyName, byte[] userId)
    	{
    		//need to add - lock id, isAdmin, key name, open_mode (ENUM - Manual - Auto - Notification - NOT Parking {will be in another list})
    		data.append(eKey, 0, eKey.length);
    		data.append(lockName, 0, lockName.length);
    		data.append(keyName, 0, keyName.length);
    		data.append(userId, 0, userId.length);
    	}
    	
    	public byte[] getEKey()
    	{
    		int start = 0;
    		int end = start + Utils.BLE_EKEY_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    	
    	public byte[] getUser()
    	{
    		int start = Utils.BLE_EKEY_LENGTH + Utils.LOCK_NAME_LENGTH + Utils.KEY_NAME_LENGTH;
    		int end = start + Utils.USER_ID_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    	
    	public byte[] getLockName()
    	{
    		int start = Utils.BLE_EKEY_LENGTH;
    		int end = start + Utils.LOCK_NAME_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    	
    	public byte[] getKeyName()
    	{
    		int start = Utils.BLE_EKEY_LENGTH + Utils.LOCK_NAME_LENGTH;
    		int end = start + Utils.KEY_NAME_LENGTH;
    		return Arrays.copyOfRange(data.buffer(), start, end); 
    	}
    	
		public void setLockName(byte[] lockName)
		{
			
		}

		public void setKeyName(byte[] keyName)
		{
			
		}

		public void setUserName(byte[] userName)
		{
			
		}

		public void setEKey(byte[] eKey)
		{
			
		}

		public void setRole(byte[] role)
		{
			
		}

		public void setOpenMode(byte[] openMode)
		{
			
		}

		public void setLockID(byte[] lockID)
		{
			
		}
    }
    
    private static class ParkingKeys {
    	private static final int fullSize = Utils.LOCK_NAME_LENGTH;// + Utils.LOCK_ID;
    	private ByteArrayBuffer data = new ByteArrayBuffer(this.fullSize);
    	
    	public static int getParkingDataSize() { return fullSize; }
    	
    	ParkingKeys(byte[] lockName)
    	{
    		data.append(lockName, 0, lockName.length);
    	}
    }
    
    private static byte[] getLocks(Context context)
    {
    	String locks = null;
    	byte[] array = {};
    	
		try {
		       SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		       locks = pref.getString(STR_LOCK_LIST, "");
		       if (!locks.equals("")) {
		    	   array = Base64.decode(locks, Base64.DEFAULT);
		       }
		       return array;
		       //return locks.getBytes();
			} 	catch (IllegalArgumentException e) {
				Log.e("Utils", "getLocks: catch general exception");
				e.printStackTrace();
				return array;
			}
    }
    
    public static void setLocks(Context context, byte[] locks)
    {
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		String str_locks = Base64.encodeToString(locks, Base64.DEFAULT);
		
		//int fullSize = Utils.BLE_EKEY_LENGTH + Utils.LOCK_NAME_LENGTH + Utils.KEY_NAME_LENGTH;
		//if (str_locks.length() % fullSize != 0)
			//return;
		editor.putString(STR_LOCK_LIST, str_locks);
		
		// Commit the edits!
		editor.commit();
       return;
    }
    
    private static void initLockList1(Context context)
    {
    	if (keyList != null)
    		return;
    	
    	byte[] locks = getLocks(context);
    	
    	keyList1 = new ArrayList<KeyData1>();

    	int len = locks.length;
    	int fullSize = KeyData1.getKeyDataSize();//Utils.BLE_EKEY_LENGTH + Utils.LOCK_NAME_LENGTH + Utils.KEY_NAME_LENGTH + Utils.USER_ID_LENGTH;
    	

    	if (len == 0)
    		return;
    	
    	int start = 3;
    	int end;
    	
    	//we know that 1st 2 bytes are 00
    	int numKeys = locks[2];
    	for (int i = 0; i < numKeys; i++)
    	{
    		//get key data
    		int keyType = locks[start];
    		int keyDataLength = locks[start + 1];
    		end = start + 2 + keyDataLength;
    		byte[] key = Arrays.copyOfRange(locks, start + 2, end);
    		// explore key fields
    		int current = 0;
    		int length = 0;
    		int field = key[current];
    		KeyData1 keyData1 = new KeyData1();
    		while (current < key.length) {
	    		switch (field) {
		    		case ENUM_STR_LOCK_NAME:
		    			length = key[current + 1];
		    			ByteArrayBuffer lockName = new ByteArrayBuffer(length);
		    			lockName.append(key, current + 2, current + 2 + length);
		    			keyData1.setLockName(lockName.buffer());
		    			break;
		    		case ENUM_STR_KEY_NAME:
		    			length = key[current + 1];
		    			ByteArrayBuffer keyName = new ByteArrayBuffer(length);
		    			keyName.append(key, current + 2, current + 2 + length);
		    			keyData1.setKeyName(keyName.buffer());
		    			break;
		    		case ENUM_STR_USER_NAME:
		    			length = key[current + 1];
		    			ByteArrayBuffer userName = new ByteArrayBuffer(length);
		    			userName.append(key, current + 2, current + 2 + length);
		    			keyData1.setUserName(userName.buffer());
		    			break;
		    		case ENUM_STR_EKEY:
		    			length = key[current + 1];
		    			ByteArrayBuffer eKey = new ByteArrayBuffer(length);
		    			eKey.append(key, current + 2, current + 2 + length);
		    			keyData1.setEKey(eKey.buffer());
		    			break;
		    		case ENUM_STR_ROLE:
		    			length = key[current + 1];
		    			ByteArrayBuffer role = new ByteArrayBuffer(length);
		    			role.append(key, current + 2, current + 2 + length);
		    			keyData1.setRole(role.buffer());
		    			break;
		    		case ENUM_STR_OPEN_MODE:
		    			length = key[current + 1];
		    			ByteArrayBuffer openMode = new ByteArrayBuffer(length);
		    			openMode.append(key, current + 2, current + 2 + length);
		    			keyData1.setOpenMode(openMode.buffer());
		    			break;
		    		case ENUM_STR_LOCK_ID:
		    			length = key[current + 1];
		    			ByteArrayBuffer lockID = new ByteArrayBuffer(length);
		    			lockID.append(key, current + 2, current + 2 + length);
		    			keyData1.setLockID(lockID.buffer());
		    			break;
	    			default:
	    				break;
	    		}
	    		current += (2 + length);
    		}
    		keyList1.add(keyData1);
    		
    		
    		// get next key
    		start = end + 1;
    	}
    

    	return;
    }
    
    private static void initLockList(Context context)
    {
    	if (keyList != null)
    		return;
    	
    	byte[] locks = getLocks(context);
    	
    	keyList = new ArrayList<KeyData>();

    	int len = locks.length;
    	int fullSize = KeyData.getKeyDataSize();//Utils.BLE_EKEY_LENGTH + Utils.LOCK_NAME_LENGTH + Utils.KEY_NAME_LENGTH + Utils.USER_ID_LENGTH;
    	
//    	assert len == 0;
//    	assert (len % fullSize != 0);
    	

    	if (len == 0 || len % fullSize != 0)
    		return;
    	
    	int start, end;
    	for (int i=0; i< len / fullSize; i++)
    	{
    		start = i * fullSize;
    		end = start + Utils.BLE_EKEY_LENGTH;
    		byte[] eKey = Arrays.copyOfRange(locks, start, end);
    		start += Utils.BLE_EKEY_LENGTH;
    		end = start + Utils.LOCK_NAME_LENGTH;
    		byte[] lockName = Arrays.copyOfRange(locks, start, end);
    		start += Utils.LOCK_NAME_LENGTH;
    		end = start + Utils.KEY_NAME_LENGTH;
    		byte[] keyName = Arrays.copyOfRange(locks, start, end);
    		start += Utils.KEY_NAME_LENGTH;
    		end = start + Utils.USER_ID_LENGTH;
    		byte[] userId = Arrays.copyOfRange(locks, start, end);
    		KeyData keyData = new KeyData(eKey, lockName, keyName, userId);
    		keyList.add(keyData);
    	}
    	
    	//convert persistent data to new format
    	// delete current data
    	//////////Utils.removeAllKeys(context);
    	//loop on keys and call addKey1
    	
    	
    	return;
    }
    
    public int getLockListSize()
    {
    	return keyList.size();
    }
    
    public KeyData getKeyDataAt(int index)
    {
    	return keyList.get(index);
    }
    
    public static void addKey(Context context, byte[] lockName, byte[] keyName, byte[] eKey, byte[] userId)
    {
//    	assert lockName.length != Utils.LOCK_NAME_LENGTH;
//    	assert keyName.length != Utils.KEY_NAME_LENGTH;
//    	assert eKey.length != Utils.BLE_EKEY_LENGTH;
    	
    	
    	Utils.initLockList(context);
    	KeyData keyData = new KeyData(eKey, lockName, keyName, userId);
    	keyList.add(keyData);
    	//update persistent data
    	byte[] keys = Utils.getLocks(context);
    	ByteArrayBuffer sKeys = new ByteArrayBuffer(keys.length+Utils.BLE_EKEY_LENGTH+Utils.LOCK_NAME_LENGTH+Utils.KEY_NAME_LENGTH+Utils.USER_ID_LENGTH);
    	sKeys.append(keys, 0, keys.length);
    	sKeys.append(eKey, 0, Utils.BLE_EKEY_LENGTH);
    	sKeys.append(lockName, 0, Utils.LOCK_NAME_LENGTH);
    	sKeys.append(keyName, 0, Utils.KEY_NAME_LENGTH);
    	sKeys.append(userId, 0, Utils.USER_ID_LENGTH);
    	
    	int l = sKeys.length();
    	Utils.setLocks(context, sKeys.buffer());
    }
    
    public static void addKey1(Context context, byte[] lockName, byte[] keyName, byte[] eKey, byte[] userId)
    {
//    	assert lockName.length != Utils.LOCK_NAME_LENGTH;
//    	assert keyName.length != Utils.KEY_NAME_LENGTH;
//    	assert eKey.length != Utils.BLE_EKEY_LENGTH;
    	
    	
    	Utils.initLockList(context);
    	KeyData keyData = new KeyData(eKey, lockName, keyName, userId);
    	keyList.add(keyData);
    	//update persistent data
    	byte[] keys = Utils.getLocks(context);
    	ByteArrayBuffer sKeys = new ByteArrayBuffer(keys.length+Utils.BLE_EKEY_LENGTH+Utils.LOCK_NAME_LENGTH+Utils.KEY_NAME_LENGTH+Utils.USER_ID_LENGTH);
    	sKeys.append(keys, 0, keys.length);
    	sKeys.append(eKey, 0, Utils.BLE_EKEY_LENGTH);
    	sKeys.append(lockName, 0, Utils.LOCK_NAME_LENGTH);
    	sKeys.append(keyName, 0, Utils.KEY_NAME_LENGTH);
    	sKeys.append(userId, 0, Utils.USER_ID_LENGTH);
    	
    	int l = sKeys.length();
    	Utils.setLocks(context, sKeys.buffer());
    }
    
    public static void removeKey(Context context, String keyName)
    {
    	//done of the string or on array??
    	//what about keeping the key name and UUID?
    }
    
    public static void removeAllKeys(Context context)
    {
    	if (keyList != null)
    		keyList.clear();
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		editor.remove(STR_LOCK_LIST);
		
		// Commit the edits!
		editor.commit();
       return;
    }
    
    public static boolean hasKeyForLock(Context context, byte[] lock)
    {
    	Utils.initLockList(context);
    	for (int i=0; i<keyList.size(); i++)
    	{
    		KeyData keyData = keyList.get(i);
    		byte[] lockName = keyData.getLockName();
    		if (Arrays.equals(lockName, lock))
    			return true;
    	}
    	return false;	
    }
    
    public static byte[] getKeyForLock(Context context, byte[] lock)
    {
    	Utils.initLockList(context);
    	String Lock = new String(lock);
    	int size = keyList.size();
    	for (int i=0; i<size; i++)
    	{
    		//scan backward in case there are newer keys with same lock name
    		int j = size - 1 - i;
    		String name = new String(keyList.get(j).getLockName());
    		if (name.equals(Lock))
    			return keyList.get(j).getEKey();
    	}
    	return null;	
    }
    
    public static byte[] getUserForLock(Context context, byte[] lock)
    {
    	Utils.initLockList(context);
    	String Lock = new String(lock);
    	for (int i=0; i<keyList.size(); i++)
    	{
    		String name = new String(keyList.get(i).getLockName());
    		if (name.equals(Lock))
    			return keyList.get(i).getUser();
    	}
    	return null;	
    }
    
    public static byte[] getAppId(Context context)
    {
    	String s=null;
    	//check if appId has been generated by random
    	
		try {
	       SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
	       String tmp = pref.getString(STR_APP_ID, null);
	       if (tmp != null) {
	    	   byte[] appId = Base64.decode(tmp, Base64.DEFAULT);
	    	   return appId;
	       }
	       //return locks.getBytes();
		} 	catch (Exception e) {
			Log.e("Utils", "getLocks: catch general exception");
			e.printStackTrace();
			return null;
		}
    	//return android.telephony.TelephonyManager.getDeviceId();
    	TelephonyManager telephonyManager = (TelephonyManager)context.getSystemService(Context.TELEPHONY_SERVICE);
    	s = telephonyManager.getDeviceId();
    	if (s == null) {
    		//generate an ID and store in memory
    		byte[] tmp = new byte[Utils.APP_ID_LENGTH];
    		new Random().nextBytes(tmp);
    		setAppId(context, tmp);
    		return tmp;
    	} else {
    		int len = s.length();
    		if (len > Utils.APP_ID_LENGTH)
    			return Arrays.copyOf(s.getBytes(), Utils.APP_ID_LENGTH);
    		else {
    			ByteArrayBuffer tmp = new ByteArrayBuffer(Utils.APP_ID_LENGTH);
    			int toFill = Utils.APP_ID_LENGTH;
    			while (toFill > 0) {
    				tmp.append(s.getBytes(), 0, (toFill > len ? len : toFill));
    				toFill -= len;
    			}
    			
    			return tmp.buffer();
    		}
    	}
    }
    
    private static void setAppId(Context context, byte[] appId)
    {
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		String str_appId = Base64.encodeToString(appId, Base64.DEFAULT);

		editor.putString(STR_APP_ID, str_appId);
		
		// Commit the edits!
		editor.commit();
       return;
    }
    
	public static boolean IsBleServiceRunning(Context context) {
	    ActivityManager manager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
    	String name = BluetoothLeService.class.getName();
	    for (RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
	    	String serviceName = service.service.getClassName();
	        if (name.equals(serviceName)) {
	            return true;
	        }
	    }
	    return false;
	}
	
	public static void startBleService(Context context)
	{
        if (!Utils.IsBleServiceRunning(context))
        {
        	ComponentName name;
        	name = context.startService(new Intent(context, BluetoothLeService.class));
        	String sName = name.toString();
        	Log.d("Utils", "started service - component name =" + sName);
        }
	}
	
	public static void stopBleService(Context context)
	{
        if (Utils.IsBleServiceRunning(context))
        	context.stopService(new Intent(context, BluetoothLeService.class));
	}
	
	public static void setServiceOn(Context context, boolean b)
	{
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		
		editor.putBoolean(Utils.STR_SERVICE_ON, b);
		
		// Commit the edits!
		editor.commit();
       return;
	}
	
	public static boolean getServiceOn(Context context)
	{
	       SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
	       boolean b = pref.getBoolean(STR_SERVICE_ON, false);
	       return b;
	}
	
	public static boolean IsAppProtected(Context context)
    {
    	boolean b = false;
		try {
		       SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		       b = pref.getBoolean(STR_APP_PROTECTED, false);
		       //return locks.getBytes();
			} 	catch (IllegalArgumentException e) {
				Log.e("Utils", "IsAppProtected: catch general exception");
				e.printStackTrace();
			}
		return b;
    }
    
    public static void setAppProtected(Context context, boolean protect)
    {
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		
		editor.putBoolean(STR_APP_PROTECTED, protect);
		
		// Commit the edits!
		editor.commit();
       return;
    }
	
    public static String getAppProtectionCode(Context context)
    {
    	String code = null;
 
    	
		try {
		       SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		       code = pref.getString(STR_APP_PROTECTION_CODE, "");
		       //return locks.getBytes();
			} 	catch (IllegalArgumentException e) {
				Log.e("Utils", "getAppProtectionCode: catch general exception");
				e.printStackTrace();
			}
		return code;
    }
    
    public static void setAppProtectionCode(Context context, String code)
    {
        SharedPreferences pref = context.getSharedPreferences(TAG, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = pref.edit();
		
		editor.putString(STR_APP_PROTECTION_CODE, code);
		
		// Commit the edits!
		editor.commit();
       return;
    }
    
    public static byte[] getFileAsByteArray(Context context, int resource)
    {
    	byte[] data = null;
        try {
            // Very simple code to copy a picture from the application's
            // resource into the external file.  Note that this code does
            // no error checking, and assumes the picture is small (does not
            // try to copy it in chunks).  Note that if external storage is
            // not currently mounted this will silently fail.
        	File file;
        	byte[] fileData = null;
            InputStream is = context.getResources().openRawResource(resource);
            data = new byte[is.available()];
            is.read(data);
            is.close();
        } catch (IOException e) {
            // Unable to create file, likely because external storage is
            // not currently mounted.
        }
        
		return data;
    }

// receive the name of text file stored in download folder
// and return string

//     readFromDownloadFolder("data.txt");


//    public static String readFromDownloadFolder(String path) {
    public static byte[] readFromDownloadFolder(String path) {

        return readFromFile(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath(), path);
    }



//    public static String readFromFile(String rootPath, String path) {
    public static byte[] readFromFile(String rootPath, String path)
    {

        StringBuilder builder = new StringBuilder();

        File file = new File(rootPath, path);
        byte[] fileData = null;
        try {
        	fileData = new byte[(int) file.length()];
        	DataInputStream dis = new DataInputStream(new FileInputStream(file));
        	dis.readFully(fileData);
        	dis.close();
        	
//            BufferedReader reader = new BufferedReader(new FileReader(file));
//            String line;
//            while ((line = reader.readLine()) != null) {
//                builder.append(line);
//            }
        } catch (FileNotFoundException e) {
            Log.d("File", "File not found - " + file.getAbsolutePath());
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Log.d("File",builder.toString() + "");

//        return builder.toString();
        return fileData;
    }

    
    public static byte[] toBytes(int num, int numBytes)
    {
    	if (numBytes < 2 || numBytes >4)
    		return null;
		byte[] result = new byte[numBytes];
		
		for (int i=0; i<numBytes; i++)
		{
			result[i] = (byte) (num >> (i*8));
		}
		
//		result[0] = (byte) (num >> 24);
//		result[1] = (byte) (num >> 16);
//		result[2] = (byte) (num >> 8);
//		result[3] = (byte) (num /*>> 0*/);
		
		return result;
    }
    
    public static int toInt(byte[] b) 
    {
    	if (b.length == 4)
	        return   b[0] & 0xFF |
	                (b[1] & 0xFF) << 8 |
	                (b[2] & 0xFF) << 16 |
	                (b[3] & 0xFF) << 24;
    	else if (b.length == 2)
	        return   b[0] & 0xFF |
	                (b[1] & 0xFF) << 8;
    	else return -1;
    }

    private static final int sizeOfIntInHalfBytes = 2;
    private static final int numberOfBitsInAHalfByte = 2;
    private static final int halfByte = 0x0F;
    private static final char[] hexDigits = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    public static String decToHex(int dec) {
        StringBuilder hexBuilder = new StringBuilder(sizeOfIntInHalfBytes);
        hexBuilder.setLength(sizeOfIntInHalfBytes);
        for (int i = sizeOfIntInHalfBytes - 1; i >= 0; --i)
        {
            int j = dec & halfByte;
            hexBuilder.setCharAt(i, hexDigits[j]);
            dec >>= numberOfBitsInAHalfByte;
        }
        return hexBuilder.toString();
    }
    
    //
 
}
