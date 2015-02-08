package com.multlock.key;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Binder;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.util.Base64;
import android.util.Log;
import android.util.SparseArray;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnLongClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.http.util.ByteArrayBuffer;

import com.multlock.key.BleUtils.bleDevice;
import com.multlock.key.BleUtils.lockKeyData;

public class MainActivity extends Activity implements BleInterface{
	
    private byte runningSeq = 0;
	
    private static final String TAG = "MTLT_MAIN";
	
    public static BleUtils ble;
    
    public static Handler mHandler = null;
    
    private boolean useExternalFile = true;
    
    private byte[] lastRes;
    
    private byte[] eUserKey;
    
    Context context;
    
    TextView DeviceConn = null;
    
    EditText tvOutput = null;
    
    EditText input1 = null;
    EditText input2 = null;
    
	public static Object object = new Object();
    
    //parameters to support communication test
    byte[] BlePublicKey = new byte[Utils.PUBLIC_KEY_LENGTH];
    byte[] BleEcdsaPublicKey = new byte[Utils.ECDSA_PUBLIC_KEY_LENGTH];

	public static byte[] lastRandom = "this is the random num of mobile".getBytes();
	public static byte[] appId = "application id 1".getBytes();
    byte[] userId = "admin           ".getBytes();
    byte[] newUserId = "lock user 123456".getBytes();
    byte[] prevCode = "000000".getBytes();
    public static byte[] newCode = "000000".getBytes();
	byte[] newUserPIN = "usrpin".getBytes();
	byte[] eKey = null;
	//byte[] lockName = "Mul-T-Lock 007-1".getBytes();
	byte[] newLockName = "Started         ".getBytes();
	byte[] lockName;
	byte[] ownerKeyName = "Owner Key 123456".getBytes();
	byte[] userKeyName = "User Key 1234567".getBytes();
	byte handShakeId = 0;
	
	private boolean p_mute;
	private boolean p_auto;
	private boolean p_locked;
	private boolean p_closed;
	private boolean p_charging;
	private int p_b_state;
	private byte p_battery;
	
	private int preferredStart = 0;
	private int preferredSize = 256;
	
	
	private boolean mBinded=false;
	
	private final boolean useFinalList = true;
	
	BluetoothLeService mBluetoothLeService;
	
	private int update_count = 1; 
	
	public static boolean skipDisconnect = false;
	
    private static final boolean securityOn = true;
    
    private String currentDeviceName = "*";
    
    private long startTime;
    private long endTime;
    private long diffTime;

    private boolean getDeviceInfoPending = false;
    private boolean getErrorsPending = false;


	// callback on bind 
	ServiceConnection connection = new ServiceConnection() {

		@Override
		public void onServiceDisconnected(ComponentName name) {
			mBinded = false;
			//mBluetoothLeService = null;
		}

		@Override
		public void onServiceConnected(ComponentName name, IBinder service) {
			Binder mLocalBinder = (com.multlock.key.BluetoothLeService.Binder) service;
			mBluetoothLeService = ((com.multlock.key.BluetoothLeService.Binder) mLocalBinder).getService();
			mBinded = true;
		}
	};
    


	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		context = this;
		
		setContentView(R.layout.activity_main);
		setProgressBarIndeterminate(true);
		
		if (Utils.getServiceOn(context))
			if (!Utils.IsBleServiceRunning(context))
				Utils.startBleService(context);
			else {
				Intent mIntent = new Intent(this, BluetoothLeService.class);
				bindService(mIntent, connection, BIND_AUTO_CREATE);
			}


		DeviceConn = (TextView)findViewById(R.id.textView1);
		tvOutput = (EditText)findViewById(R.id.editText1);
		input1 = (EditText)findViewById(R.id.input1);
		input2 = (EditText)findViewById(R.id.input2);
		
	    mHandler = new Handler() {
	        @Override
	        public void handleMessage(Message msg) {

	        	switch (msg.what) {
	        	case 0:
	            	Toast.makeText(context, "Response Char changed", Toast.LENGTH_SHORT).show();
	        		break;
	        	case 1:
	        		break;
	        	case 2:
	        		Toast.makeText(context, "Discovering Services...", Toast.LENGTH_SHORT).show();
	        		break;
	        	case 3:
	        		Toast.makeText(context, "Device Disconnected!!", Toast.LENGTH_SHORT).show();
	        		String s = DeviceConn.getText().toString();
	        		DeviceConn.setText("Disconnected... " + s);
	        		break;
	        	case 4:
	        		//long elapsed = time_after - time_before;
	        		//String s_elapsed = Long.toString(elapsed);
	        		//Toast.makeText(context, "Write callback to Command Char - time: " + s_elapsed + " milli sec", Toast.LENGTH_SHORT).show();
	        		//Log.d(TAG, "Write time elapsed: " + s_elapsed + " milli sec");
	        		break;
	        	case 5:
	        		Toast.makeText(context, "Write to Command Char FAILED!!", Toast.LENGTH_SHORT).show();
	        		break;
	        	case 6:
	        		Toast.makeText(context, "Request Succeeded", Toast.LENGTH_SHORT).show();
	        		break;
	        	case 7:
	        		Toast.makeText(context, "Request Failed", Toast.LENGTH_SHORT).show();
	        		break;
	        	case 8:
	        		Toast.makeText(context, "Services not found!!", Toast.LENGTH_SHORT).show();
	        		DeviceConn.setText("Did not discover critical services!!!");
	        		break;
	        	case 9:
	        		Toast.makeText(context, "Checksum Error in Response!!", Toast.LENGTH_SHORT).show();
	        		break;
	        	case 10:
	        		Intent intent = new Intent(context.getApplicationContext(), SecPage.class);
	        		intent.setAction(Intent.ACTION_VIEW);
	        		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
	        		startActivity(intent);
	        		break;
	    		case Utils.ENUM_CMD_UNLOCK_RESPONSE:
	        		Toast.makeText(context, "Door unlocked successfully", Toast.LENGTH_SHORT).show();
	        		break;
	    		case Utils.ENUM_CMD_LOCK_RESPONSE:
	        		Toast.makeText(context, "Door locked successfully", Toast.LENGTH_SHORT).show();
	        		break;
	    		case Utils.ENUM_CMD_CREATE_NEW_KEY_RESPONSE:
	        		Toast.makeText(context, "New Key Created successfully", Toast.LENGTH_SHORT).show();
	        		break;
	        	case 100:
	        		Bundle b = msg.getData();
	        		s = b.getString("HANDLER_MESSAGE");
	        		//Toast.makeText(context, s, Toast.LENGTH_SHORT).show();
	        		tvOutput.setText(s);
	        		break;
	        	case 101:
	        		b = msg.getData();
	        		s = b.getString("HANDLER_MESSAGE");
	        		//Toast.makeText(context, s, Toast.LENGTH_SHORT).show();
	        		DeviceConn.setText(s);
	        		break;
	        	case 50:
	        		try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        		requestPublicKey();
	        		break;
	        	case 51:
	        		try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        		doKDF();
	        		break;
	        	case Utils.ENUM_CMD_SET_OWNER_ACK:
	        		try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        		ble.sendAck(Utils.ENUM_CMD_SET_OWNER_ACK);
	        		break;
	        	case Utils.ENUM_CMD_GET_NEW_KEY_ACK:
	        		try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        		ble.sendAck(Utils.ENUM_CMD_GET_NEW_KEY_ACK);
	        		break;
	        	case Utils.ENUM_CMD_GET_DEVICE_CONFIG_RESPONSE_ACK:
	        		try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        		ble.sendAck(Utils.ENUM_CMD_GET_DEVICE_CONFIG_RESPONSE_ACK);
	        		break;
	        	case Utils.ENUM_CMD_HANDSHAKE1:
	        		try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        		doHandshake();
	        		break;
	        	case Utils.ENUM_CMD_OTA_UPDATE:
	        		Toast.makeText(context, "Received Params Response ", Toast.LENGTH_SHORT).show();
	        		doOTA();
	        		break;
	        	case Utils.ENUM_CMD_DOWNLOAD_COMPLETE_RESPONSE:
	        		Toast.makeText(context, "status = " + (msg.arg1==0?" OK ":" Error " + msg.arg1) + "  content = " + msg.arg2, Toast.LENGTH_SHORT).show();
	        		break;
	        	case Utils.ENUM_CMD_DOWNLOAD_CHUNK_STATUS:
	        		int status = msg.arg1;
	        		if (status != 0)
	        			resendChunk(msg.arg2);
	        		break;
	        	case 999:
	        		BluetoothGatt gatt = (BluetoothGatt)msg.obj;
					ble.enableNextCharacteristic(gatt);
					ble.advance();
					break;

                case Utils.ENUM_CMD_GET_IV_RESPONSE:
                    if (getDeviceInfoPending) {
                        doGetDeviceInfo();
                        break;
                    } else if (getErrorsPending) {
                        doGetErrors();
                        break;
                    }
                    break;
                }
	        	
	            RadioGroup rg1 = (RadioGroup) findViewById(R.id.radioGroup1);        
	            rg1.clearCheck();
	            RadioGroup rg2 = (RadioGroup) findViewById(R.id.radioGroup2);        
	            rg2.clearCheck();
	        	
	            return;
	        }
	    };
	    
	    
	    //ble.init(this, mHandler, this);

	    //*** ADDED FOR SECURITY INTEGRATION
	    if (securityOn)
	    {
	    	boolean b = SecUtils.secInit(this);
	    	if (!b)
	    		Toast.makeText(this, "Failed to init security", Toast.LENGTH_SHORT).show();
	    }
//		testECDH();
	    
	}
	
    private void testECDH()
    {
//    	Private:
//    		cc31304e e0902b88 8afd6000 2021e4ee c347e8db 73ced91f 2ac3e2e8 165f92f2 8e67f409 fd66bf5e dad487eb 985e52bf f9054c80 deabe4d3 d6a15991 dc800a5b
//
//    		Public:
//    		69b6022d d2386d7e fe3bb818 8c184ae3 e6f31ba5 b21ba036 02635715 fe09c118 cc31304e e0902b88 8afd6000 2021e4ee c347e8db 73ced91f 2ac3e2e8 165f92f2
    	byte[] privateKey = {(byte)0xcc,(byte)0x31,(byte)0x30,(byte)0x4e,(byte)0xe0,(byte)0x90,(byte)0x2b,(byte)0x88,(byte)0x8a,(byte)0xfd,(byte)0x60,(byte)0x00,(byte)0x20,(byte)0x21,(byte)0xe4,(byte)0xee,(byte)0xc3,(byte)0x47,(byte)0xe8,(byte)0xdb,(byte)0x73,(byte)0xce,(byte)0xd9,(byte)0x1f,(byte)0x2a,(byte)0xc3,(byte)0xe2,(byte)0xe8,(byte)0x16,(byte)0x5f,(byte)0x92,(byte)0xf2,(byte)0x8e,(byte)0x67,(byte)0xf4,(byte)0x09,(byte)0xfd,(byte)0x66,(byte)0xbf,(byte)0x5e,(byte)0xda,(byte)0xd4,(byte)0x87,(byte)0xeb,(byte)0x98,(byte)0x5e,(byte)0x52,(byte)0xbf,(byte)0xf9,(byte)0x05,(byte)0x4c,(byte)0x80,(byte)0xde,(byte)0xab,(byte)0xe4,(byte)0xd3,(byte)0xd6,(byte)0xa1,(byte)0x59,(byte)0x91,(byte)0xdc,(byte)0x80,(byte)0x0a,(byte)0x5b};
    	byte[] publicKey = {(byte)0x69,(byte)0xb6,(byte)0x02,(byte)0x2d,(byte)0xd2,(byte)0x38,(byte)0x6d,(byte)0x7e,(byte)0xfe,(byte)0x3b,(byte)0xb8,(byte)0x18,(byte)0x8c,(byte)0x18,(byte)0x4a,(byte)0xe3,(byte)0xe6,(byte)0xf3,(byte)0x1b,(byte)0xa5,(byte)0xb2,(byte)0x1b,(byte)0xa0,(byte)0x36,(byte)0x02,(byte)0x63,(byte)0x57,(byte)0x15,(byte)0xfe,(byte)0x09,(byte)0xc1,(byte)0x18,(byte)0xcc,(byte)0x31,(byte)0x30,(byte)0x4e,(byte)0xe0,(byte)0x90,(byte)0x2b,(byte)0x88,(byte)0x8a,(byte)0xfd,(byte)0x60,(byte)0x00,(byte)0x20,(byte)0x21,(byte)0xe4,(byte)0xee,(byte)0xc3,(byte)0x47,(byte)0xe8,(byte)0xdb,(byte)0x73,(byte)0xce,(byte)0xd9,(byte)0x1f,(byte)0x2a,(byte)0xc3,(byte)0xe2,(byte)0xe8,(byte)0x16,(byte)0x5f,(byte)0x92,(byte)0xf2};    
    	SecUtils.setRemoteAESPublicKey(privateKey);
    	PublicKey rKey = SecUtils.getRemoteAESPublic();
    	PrivateKey pKey = SecUtils.getPrivateKey();
    	byte[] secret = SecUtils.syncECDH();
    }

	
    @Override
    protected void onStart() {
        super.onStart();
    	if (mBinded) {
    		//take list from service
    		ble = this.mBluetoothLeService.getBle();
    	} else {
    		ble = new BleUtils();
            ble.init(this, mHandler, this);
    	}

		
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        //ble.init(this, mHandler, this);
    }
    
    
    @Override
    protected void onPause() {
        super.onPause();
        //Cancel any scans in progress
        //disconnectBLE();
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        //Cancel any scans in progress
        //disconnectBLE();
        if (!mBinded)
        	ble.close(0);
    }
    
    private void disconnectBLE()
    {
        if (!mBinded && !skipDisconnect) {
	        ble.disconnect(0);
	        ble.clearDevices();
        }
    }

    
    @Override
    protected void onStop() {
        super.onStop();
        if(mBinded) {
        	unbindService(connection);
        	mBinded = false;
        } else {
        	//if (!skipDisconnect)
        		//disconnectBLE();
        }
    }
 

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
    	super.onPrepareOptionsMenu(menu);
        // Add the "scan" option to the menu
        //getMenuInflater().inflate(R.menu.settings, menu);
    	/*
        //Add any device elements we've discovered to the overflow menu
        for (int i=0; i < ble.getDeviceSize(); i++) {
        	int id = ble.getKey(i);
        	String name = ble.getDeviceName(i);
            menu.add(0, id, 0, name);
        }
*/
        return true;
    }
    
    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
    	super.onPrepareOptionsMenu(menu);
    	menu.clear();
    	getMenuInflater().inflate(R.menu.settings, menu);

    	Log.d("MTLT_BLE", "onPrepareOptionsMenu - loop");
        for (int i=0; i < ble.getDeviceSize(useFinalList); i++) {
        	//int id = ble.getKey(i);
        	int id = i;
        	String name = ble.getDeviceName(useFinalList, i);
            menu.add(0, id, 0, name);
        }
        if (ble.getDeviceSize(useFinalList) == 0)
        	menu.add(0, ble.getDeviceSize(useFinalList), 0, "dummy entry");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.menu_settings:
    			if (Utils.IsBleServiceRunning(context) && !mBinded)
    			{
    				Intent mIntent = new Intent(this, BluetoothLeService.class);
    				bindService(mIntent, connection, BIND_AUTO_CREATE);
    			}
            	if (!mBinded) {
	                ble.clearDevices();
	                int interval = 3000;
	                ble.scanMTLTDevices(interval);
	                Toast.makeText(context, "scanning", Toast.LENGTH_SHORT).show();
	                
	    			try {
	    				// wait for previous write to end
	    				synchronized (object) {
	    					// long time1 = System.currentTimeMillis();
	    					Log.d("MTLT_BLE", "before WAIT");
	    					//object.wait(interval + 2000);
	    					object.wait(200);
	    					Log.d("MTLT_BLE", "after WAIT");
	    					//long time2 = System.currentTimeMillis();
	    					// long delta = time2 - time1;
	    					//Log.i(TAG, "payload sending time: " + time2);

	    				}
	    			} catch (InterruptedException e) {
	    				// TODO Auto-generated catch block
	    				e.printStackTrace();
	    			} catch (IllegalMonitorStateException e) {
	    				// TODO Auto-generated catch block
	    				e.printStackTrace();
	    			}
//	                try {
//						Thread.sleep(interval + 4000);
//					} catch (InterruptedException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					}
            	} else {
            		//take list from service
            	}
                setProgressBarIndeterminateVisibility(true);
                return true;
            default:
                //Obtain the discovered device to connect with
            	int item_id = item.getItemId();
            	//String name = ble.getDeviceNameByKey(item_id);
            	String name = ble.getDeviceName(true, item_id);
//            	currentDeviceName = name;
            	currentDeviceName = "Started        ";
            	ByteArrayBuffer lock = new ByteArrayBuffer(Utils.LOCK_NAME_LENGTH);
            	byte[] spaces = "                ".getBytes();
            	if (name != null)
            	{
            		lock.append(name.getBytes(), 0, name.length());
            		lock.append(spaces, 0, Utils.LOCK_NAME_LENGTH - name.length());
            		lockName = lock.buffer();
            	} else {
            		lockName = "N/A".getBytes();
            	}
            	
            	startTime = System.currentTimeMillis();
                Log.i(TAG, "Connecting to " + name + " time: " + startTime);
                /*
                 * Make a connection with the device using the special LE-specific
                 * connectGatt() method, passing in a callback for GATT events
                 */
                
                int ret = ble.connectDevice(item.getItemId());
                if (ret != -1)
                {
	       			//TextView tv = (TextView)findViewById(R.id.textView1);
	       			//BluetoothDevice device = mDevices.valueAt(0);
                	bleDevice device = ble.getDevice(true, item_id);
                	byte status = device.getDeviceStatus();
                	
                	p_mute = ble.isLockMuted(status);
                	p_auto = ble.isLockAutoLocked(status);
                	p_locked = ble.isLockLocked(status);
                	p_closed = ble.isDoorClosed(status);
                	p_charging = ble.isLockCharging(status);
                	p_b_state = ble.getBatteryState(status);
                	p_battery = device.getBatteryPercents();
                	
                	

//                	String bat_state = (p_b_state == 0 ? "Low" : (p_b_state == 1 ? "Medium" : "High"));
//                	String s = device.device.getName() + " Muted: " + p_mute + " Auto: " + p_auto + " lock locked: " + p_locked
//        				+ " Door_closed: " + p_closed + " Charging: " + p_charging
//        				+ " Battery_state: " + p_b_state + " Battery_% : " + p_battery;
//            		Bundle bundle = new Bundle();
//            		Message msg = new Message();
//            		msg.what = 101;
//
//            		bundle.putString("HANDLER_MESSAGE", s);
//            		msg.setData(bundle);
//            		mHandler.sendMessage(msg);
                	Toast.makeText(this, "Connected...", Toast.LENGTH_SHORT).show();
                }
                else {
            		Toast.makeText(this, "Failed to Connect...", Toast.LENGTH_SHORT).show();
            		return true;
                }

                //Display progress UI
                //mHandler.sendMessage(Message.obtain(null, MSG_PROGRESS, "Connecting to "+device.getName()+"..."));
                return super.onOptionsItemSelected(item);
        }
    }



    
    public int getNumServices(BluetoothGatt gatt)
    {
    	List<BluetoothGattService> gattServices = gatt.getServices();
    	return gattServices.size(); 
    }
    
    public void onECDH(View v)
    {
//        if (securityOn) {
//        	this.testVerify();
//        }
        
    	requestPublicKey();
    }
    
    private void requestPublicKey()
    {
    	byte[] appId = Utils.getAppId(this);
    	String s = new String(appId);
    	
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
        //byte[] val = "this is the public key of mobile".getBytes();
        ByteArrayBuffer val = new ByteArrayBuffer(Utils.PUBLIC_KEY_LENGTH);
        byte[] key = null;
        if (securityOn)
        	key = SecUtils.getLocalPublicKey().getEncoded();
        else
        	key = SecPage.g_kpA.getPublic().getEncoded();
        
        val.append(key, key.length - Utils.PUBLIC_KEY_LENGTH, Utils.PUBLIC_KEY_LENGTH);
        
        params.putByteArray(Utils.STR_KEY, val.buffer());
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_SEND_PUBLIC_KEY);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.SendPublicKey(params);
    }
    
    public void onHandshake(View v)
    {   
    	Intent intent = getIntent();
    	finish();
    	startActivity(intent);
    	
//    	Utils.removeAllKeys(this);
//    	Utils.addKey(this, this.lockName, this.userKeyName, this.eKey, this.userId);
//    	Utils.hasKeyForLock(this, this.lockName);
//    	
//    	if (!ble.IsConnected())
//    	{
//    		mHandler.sendEmptyMessage(3);
//    		return;
//    	}
//    	
//    	doHandshake();
    }
    
    public void doHandshake()
    {
    	Bundle params = new Bundle();
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_HANDSHAKE1);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.handShake(params);
    }
    
    public void resendChunk(int chunkNum)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, (byte)Utils.ENUM_CMD_RESEND_CHUNK);
        
        params.putByteArray(Utils.STR_CHUNK_NUM, Utils.toBytes(chunkNum, Utils.CHUNK_NUM_LENGTH_16));
        
        ByteArrayBuffer chunkData = new ByteArrayBuffer(preferredSize);
        
        if (useExternalFile)
        	hexData = Utils.readFromDownloadFolder(FILE_NAME);
        else       		
        	hexData = Utils.getFileAsByteArray(this, R.drawable.d_package);
        
        chunkData.append(hexData, preferredStart + chunkNum * preferredSize, preferredSize);
        
        params.putByteArray(Utils.STR_OTA_UPDATE_DATA, chunkData.buffer());
        
        params.putInt(Utils.STR_PREFERRED_START_ADDRESS, preferredStart);
        
        params.putInt(Utils.STR_PREFERRED_CHUNK_SIZE, preferredSize);
        
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }
    
    public void doOTA()
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_OTA_UPDATE);
        
        if (useExternalFile)
        	hexData = Utils.readFromDownloadFolder(FILE_NAME);
        else       		
        	hexData = Utils.getFileAsByteArray(this, R.drawable.packge);
        
        params.putByteArray(Utils.STR_OTA_UPDATE_DATA, hexData);
        
        params.putInt(Utils.STR_PREFERRED_START_ADDRESS, preferredStart);
        
        params.putInt(Utils.STR_PREFERRED_CHUNK_SIZE, preferredSize);
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }
    
    public void onSetOwner(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    	
    	String lock = input1.getText().toString();
    	String code = input2.getText().toString();
    	//lockName = lock.getBytes();
    	newCode = code.getBytes();
        params.putByteArray(Utils.STR_PREV_ADMIN_CODE, prevCode);
        params.putByteArray(Utils.STR_ADMIN_CODE, code.getBytes());
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByteArray(Utils.STR_USER_ID, userId);
        params.putByte(Utils.STR_MODE, (byte)0);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        params.putByteArray(Utils.STR_LOCK_NAME, newLockName);
        params.putByteArray(Utils.STR_KEY_NAME, ownerKeyName);
        
        //params.putByte(Utils.STR_DEVICE_INDEX, (byte)0);
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_SET_OWNER);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.setOwner(params);
    }
    
    public void onKDF(View v)
    {
    	doKDF();
    }
    
    private void doKDF()
    {
    	
    	byte[] s_kdfId = input1.getText().toString().getBytes();
    	
//    	byte kdfId = (byte)(s_kdfId[0] - (int)'0');
		//*** ADDED FOR SECURITY INTEGRATION
    	byte kdfId = SecUtils.getPersistentHandshakeId(new String(this.lockName));
    	
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	Bundle params = new Bundle();

        params.putByte(Utils.STR_BLE_ASSOCIATION_ID, kdfId);
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_KDF);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.agreeOnKey(params);
    }
    
    public void onCreateKey(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	String code = input2.getText().toString();
    	//lockName = lock.getBytes();
    	newCode = code.getBytes();
    	
    	Bundle params = new Bundle();

        params.putByteArray(Utils.STR_ADMIN_CODE, newCode);
        params.putByteArray(Utils.STR_USER_ID, newUserId);
        params.putByteArray(Utils.STR_NEW_USER_PIN, newUserPIN);
        params.putByteArray(Utils.STR_KEY_NAME, userKeyName);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_CREATE_NEW_KEY);
        
        params.putByte(Utils.STR_EXPIRATION, (byte)3);
        params.putByte(Utils.STR_ROLE, (byte)1);
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByte(Utils.STR_PROVIDER_ID, (byte)0);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.createNewKey(params);
    }
    
    public void onGetKey(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();

        params.putByteArray(Utils.STR_USER_ID, newUserId);
        params.putByteArray(Utils.STR_NEW_USER_PIN, newUserPIN);
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByteArray(Utils.STR_KEY_NAME, userKeyName);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_GET_NEW_KEY);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.getNewKey(params);
    }
    
    public void onUnlock(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();

    	boolean useAdmin = false;
    	if (!useAdmin) {
	        params.putByteArray(Utils.STR_USER_ID, newUserId);
	        params.putByteArray(Utils.STR_KEY, eUserKey);
    	} else {
	        params.putByteArray(Utils.STR_USER_ID, userId);
	        eKey = Utils.getKeyForLock(this, lockName);
	        params.putByteArray(Utils.STR_KEY, eKey);
    	}
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByte(Utils.STR_MODE, (byte)0);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_UNLOCK);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.unlock(params);
    }
    
    public void onLock(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    	
    	boolean useAdmin = false;
    	if (!useAdmin) {
	        params.putByteArray(Utils.STR_USER_ID, newUserId);
	        params.putByteArray(Utils.STR_KEY, eUserKey);
    	} else {
	        params.putByteArray(Utils.STR_USER_ID, userId);
	        eKey = Utils.getKeyForLock(this, lockName);
	        params.putByteArray(Utils.STR_KEY, eKey);
    	}
    	
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByte(Utils.STR_MODE, (byte)0);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_LOCK);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.lock(params);
    }
    
    
    public void onAdminUnlock(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();

    	boolean useAdmin = true;
    	if (!useAdmin) {
	        params.putByteArray(Utils.STR_USER_ID, newUserId);
	        params.putByteArray(Utils.STR_KEY, eUserKey);
    	} else {
	        params.putByteArray(Utils.STR_USER_ID, userId);
	        if (eKey == null)
	        	eKey = Utils.getKeyForLock(this, lockName);
	        params.putByteArray(Utils.STR_BLE_EKEY, eKey);
    	}
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByte(Utils.STR_MODE, (byte)0);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_UNLOCK);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.unlock(params);
    }
    
    public void onAdminLock(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    	
    	boolean useAdmin = true;
    	if (!useAdmin) {
	        params.putByteArray(Utils.STR_USER_ID, newUserId);
	        params.putByteArray(Utils.STR_KEY, eUserKey);
    	} else {
	        params.putByteArray(Utils.STR_USER_ID, userId);
	        if (eKey == null)
		        eKey = Utils.getKeyForLock(this, lockName);
	        params.putByteArray(Utils.STR_BLE_EKEY, eKey);
    	}

        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByte(Utils.STR_MODE, (byte)0);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_LOCK);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.lock(params);
    }
    
    public void onSetAdminCode(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    	

        params.putByteArray(Utils.STR_USER_ID, userId);
        params.putByteArray(Utils.STR_APP_ID, appId);
//        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_SET_ADMIN_CODE);
        
    	String code = input2.getText().toString();
    	//lockName = lock.getBytes();
    	
        params.putByteArray(Utils.STR_ADMIN_CODE, code.getBytes());
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

    }
    
    
    
    public void onConfig(View v)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    	
    	byte configId = Utils.ENUM_EMULATE_LOCK_EXISTENCE;
    	byte value = (byte)1;

        params.putByte(Utils.STR_CONFIG_ID, configId);
        params.putByte(Utils.STR_CONFIG_VALUE_LENGTH, (byte)1);
        params.putByte(Utils.STR_CONFIG_VALUE, value);
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_OP_CONFIG);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);

        //ble.lock(params);
    }
    
    public void onSecPage(View v)
    {
		Intent intent = new Intent(this, SecPage.class);
		intent.setAction(Intent.ACTION_VIEW);
		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		startActivity(intent);
		return;
    }
    
    public void onClick(View v)
    {
    	RadioGroup rg1=(RadioGroup)findViewById(R.id.radioGroup1);
    	RadioGroup rg2=(RadioGroup)findViewById(R.id.radioGroup2);
	    int id= rg1.getCheckedRadioButtonId();
	    if (id == -1)
		    id= rg2.getCheckedRadioButtonId();
    	if(id!=-1){
    	    switch (id) {
    	    case R.id.radioEcdh:
    	    	onECDH(v);
    	    	break;
    	    case R.id.radioHandshake:
    	    	onHandshake(v);
    	    	break;
    	    case R.id.radioKdf:
    	    	onKDF(v);
    	    	break;
    	    case R.id.radioSetowner:
    	    	onSetOwner(v);
    	    	break;
    	    case R.id.radioAdminunlock:
    	    	onAdminUnlock(v);
    	    	break;
    	    case R.id.radioAdminlock:
    	    	onAdminLock(v);
    	    	break;
    	    case R.id.radioUserunlock:
    	    	onUnlock(v);
    	    	break;
    	    case R.id.radioUserlock:
    	    	onLock(v);
    	    	break;
    	    case R.id.radioCreatekey:
    	    	onCreateKey(v);
    	    	break;
    	    case R.id.radioGetkey:
    	    	onGetKey(v);
    	    	break;
    	    case R.id.radioSecpage:
    	    	onSecPage(v);
    	    	break;
    	    case R.id.radioGetkeys:
    	    	onGetKeys(v);
    	    	break;
    	    case R.id.radioSetadmincode:
    	    	onSetAdminCode(v);
    	    	break;
    	    case R.id.radioRecoverlock:
    	    	onRecover(v);
    	    	break;
    	    case R.id.radioGetCommVersion:
    	    	onGetCommVersion(v);
    	    	break;
    	    case R.id.radioGetDeviceInfo:
    	    	onGetDeviceInfo(v);
    	    	break;
    	    case R.id.radioSetDeviceInfo:
    	    	onSetDeviceConfig(v);
    	    	break;
    	    case R.id.radioOtaUpdate:
    	    	onOtaUpdate(v);
    	    	break;
    	    case R.id.radioInstall:
    	    	onInstall(v);
    	    	break;
    	    case R.id.radioDownloadComplete:
    	    	onDownloadComplete(v);
    	    	break;
    	    }
//    	    View radioButton = rg1.findViewById(id);
//    	    int radioId = radioGroup1.indexOfChild(radioButton);
//    	    RadioButton btn = (RadioButton) rg1.getChildAt(radioId);
//    	    String selection = (String) btn.getText();
    	}
    }
    
    //perf test params
    long time_before, time_after;
    private boolean perfOn = false;
    
    private Runnable mPerfRunnable = new Runnable() {
        @Override
        public void run() {
        	Bundle params = new Bundle();
            byte[] val = "this is the public key of mobile".getBytes();
            params.putByteArray(Utils.STR_KEY, val);
            int dummy = 0;
            while (dummy++ < 1)
            {
            	//time_before = System.currentTimeMillis();
            	time_before = System.nanoTime();
            	ble.SendPublicKey(params);
            	try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
        }
    };
    
    public void onPerf(View v)
    {
    	//Button button = (Button)findViewById(R.id.button9);
    	//if (!perfOn)
    	//{
    		//button.setText("Perf - Stop");
    		//run onECDH until stopped
    		mHandler.postDelayed(mPerfRunnable, 0);
    	//} else {
    		//button.setText("Perf - Start");
    	//}
    	//perfOn = !perfOn;

    	//this.ble.testInsertSorted();
    }
    
    public void onGetKeys(View v)
    {
    	boolean fake = false;
    	skipDisconnect = true;
    	
    	if (!fake) {
	    	
	    	String code = input2.getText().toString();
	    	try {
				byte[] newCode1 = code.getBytes();
				newCode = code.getBytes("ISO-8859-1");
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	
	    	if (!ble.IsConnected())
	    	{
	    		mHandler.sendEmptyMessage(3);
	    		return;
	    	}
	    	
	    	Bundle params = new Bundle();
	
	        params.putByteArray(Utils.STR_ADMIN_CODE, newCode);
	        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
	        
	        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_GET_KEYS);
	        params.putByteArray(Utils.STR_APP_ID, appId);
	        
	        BleUtils ble_task = new BleUtils();
	        
	        ble_task.init(this, mHandler, this);
	        
	        ble_task.execute(params);
    	} else {
    		onGetKeysResponse(null);
    	}
    }
    
    public void onRecover(View view)
    {    	
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	String code = input2.getText().toString();
    	newCode = code.getBytes();
    	
    	Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_RECOVER_OWNER);

        params.putByteArray(Utils.STR_ADMIN_CODE, newCode);
        params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByteArray(Utils.STR_USER_ID, userId);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(lastRandom));
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }
    
    public void onGetCommVersion(View view)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_GET_COMMUNICATION_VERSION);
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }

    public void onGetErrors(View view)
    {
		Intent intent = new Intent(this, getErrors.class);

    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}

        if (!SecUtils.isLastIV2Initiated())
        {
            getErrorsPending = true;
            requestIV();
            return;
        }

        doGetErrors();

    }
    
    public void onViewText(View view)
    {

    }

    private void doGetErrors()
    {
        getErrorsPending = false;
    	
    	Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_GET_ERRORS);
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);     
//
//		intent.setAction(Intent.ACTION_VIEW);
//		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
//		startActivity(intent);
		return;	
    }
    
    public void onGetDeviceInfo(View view)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}

        if (!SecUtils.isLastIV2Initiated())
        {
            getDeviceInfoPending = true;
            requestIV();
            return;
        }
    	
        doGetDeviceInfo();
    }

    private void doGetDeviceInfo()
    {
        getDeviceInfoPending = false;

        Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_GET_DEVICE_INFO);

        BleUtils ble_task = new BleUtils();

        ble_task.init(this, mHandler, this);

        ble_task.execute(params);
    }
    
    public void onSetDeviceConfig(View view)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	    	
    	Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_OP_DEVICE_CONFIG);
        
        params.putByteArray(Utils.STR_APP_ID, appId);
       
    	String old_code = input2.getText().toString();
    	
    	byte[] oldCode = old_code.getBytes();
    	
    	String code = input1.getText().toString();
    	
    	newCode = code.getBytes();
    	
    	params.putByteArray(Utils.STR_PREV_ADMIN_CODE, oldCode);

        params.putByteArray(Utils.STR_ADMIN_CODE, newCode);
        
//        Lock Config (0- Always 1) 1- Auto 0 = auto 2 - mute 
        
        params.putByte(Utils.STR_DEVICE_STATUS, (byte)0);
        
        params.putByteArray(Utils.STR_OWNER_UNLOCK_CODE, "0000".getBytes());
        
        params.putByteArray(Utils.STR_LOCK_NAME, "STARTED1        ".getBytes());
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }
    
    private byte[] hexData = {0x01, 0x02, 0x03, 0x04};
	String FILE_NAME = "d_package.bin";
    
    public void onOtaUpdate(View view)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    	
    	int preferredChunkSize = 256;
    	int preferredStartAddress = FotaBleUtils.OTABytesSent(preferredChunkSize);

        if (preferredStartAddress == 0) {

            params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_DOWNLOAD_PARAMS_REQUEST);

            if (useExternalFile)
                hexData = Utils.readFromDownloadFolder(FILE_NAME);

            else
                hexData = Utils.getFileAsByteArray(this, R.drawable.packge);

            params.putByteArray(Utils.STR_DP_LENGTH, Utils.toBytes(hexData.length, Utils.DP_LENGTH_LENGTH));

            params.putByteArray(Utils.STR_DP_FLAGS, Utils.toBytes(0, Utils.DP_FLAGS_LENGTH));
        } else {
            params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_DOWNLOAD_PARAMS_CHANGE_REQUEST);
        }
        
        params.putByteArray(Utils.STR_PREFERRED_START_ADDRESS, Utils.toBytes(preferredStartAddress, Utils.PREFERRED_START_ADDRESS_LENGTH));
        
        params.putByteArray(Utils.STR_PREFERRED_CHUNK_SIZE, Utils.toBytes(preferredChunkSize, Utils.PREFERRED_CHUNK_SIZE_LENGTH));
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }
    
    public void onInstall(View view)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    			    			
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_INSTALL_REQUEST);
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }
    
    public void onDownloadComplete(View view)
    {
    	if (!ble.IsConnected())
    	{
    		mHandler.sendEmptyMessage(3);
    		return;
    	}
    	
    	Bundle params = new Bundle();
    			    			
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_DOWNLOAD_COMPLETE);
                
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, mHandler, this);
        
        ble_task.execute(params);
    }


    private void requestIV()
    {
        if (!ble.IsConnected())
        {
            mHandler.sendEmptyMessage(3);
            return;
        }

        Bundle params = new Bundle();

        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_GET_IV);

        BleUtils ble_task = new BleUtils();

        ble_task.init(this, mHandler, this);

        ble_task.execute(params);

        //ble.SendPublicKey(params);
    }


    public void onClearAll (View v)
    {
        RadioGroup rg1 = (RadioGroup) findViewById(R.id.radioGroup1);        
        rg1.clearCheck();
        RadioGroup rg2 = (RadioGroup) findViewById(R.id.radioGroup2);        
        rg2.clearCheck();
    }

	@Override
	public void onSendPublicKeyResponse(Bundle response) {
		//*** ADDED FOR SECURITY INTEGRATION
		// here we need to store the ECDSA public key per lock
		// can use the SecUtils.setByteArrayPersist(name, bytes)
		// we also need to call HandShake - we can use doHandshake () !!
//		byte[] aes = response.getByteArray(Utils.STR_AES_KEY);
//		SecUtils.setByteArrayPersist(currentDeviceName + "-aes", aes);
//		
//		byte[] ecDsa = response.getByteArray(Utils.STR_PUBLIC_KEY);
//		SecUtils.setByteArrayPersist(currentDeviceName + "-ecdsa", ecDsa);
		
//		SecUtils.storePersistentForLock(currentDeviceName);
	}

	@Override
	public void onLeScanDeviceFound(bleDevice btDevice) {
        //Update the overflow menu
        invalidateOptionsMenu();
	}

	@Override
	public void onHandshakeResponse(Bundle response) {
		//byte[] id = Utils.getAppId(this);
		lastRandom = response.getByteArray(Utils.STR_RANDOM_KEY);
		handShakeId = response.getByte(Utils.STR_BLE_ASSOCIATION_ID);
		byte[] signature = response.getByteArray(Utils.STR_BLE_SIGNATURE);
		//need to verify signature here!!!
		mHandler.sendEmptyMessage(6);
		
	}

	@Override
	public void onSetOwnerResponse(Bundle response) {
		lastRandom = response.getByteArray(Utils.STR_RANDOM_KEY);
		eKey = response.getByteArray(Utils.STR_BLE_EKEY);
		//*** ADDED FOR SECURITY INTEGRATION
		byte[] id = response.getByteArray(Utils.STR_BLE_ASSOCIATION_ID);
		SecUtils.setPersistentHandshakeId(currentDeviceName, id[0]);
		SecUtils.storePersistentForLock(currentDeviceName);
		
		Utils.removeAllKeys(this);
		Utils.addKey(this, this.lockName, this.ownerKeyName, eKey, this.userId);
		mHandler.sendEmptyMessage(6);
	}

	@Override
	public void onLastRequestSuccess() {
		mHandler.sendEmptyMessage(6);
	}

	@Override
	public void onRequestSuccess(Bundle response) {
		// TODO Auto-generated method stub
		int cmd = response.getInt(Utils.STR_COMMAND);
		switch (cmd) {
		case Utils.ENUM_CMD_GET_NEW_KEY_RESPONSE:
		case Utils.ENUM_CMD_UNLOCK_RESPONSE:
		case Utils.ENUM_CMD_LOCK_RESPONSE:
		case Utils.ENUM_CMD_CREATE_NEW_KEY_RESPONSE:
			mHandler.sendEmptyMessage(cmd);
			break;
		default:
			break;
		}
	}

	@Override
	public void onRequestError(Bundle response) {
		// TODO Auto-generated method stub
		if (response == null)
		{
			mHandler.sendEmptyMessage(9);
			return;
		}
		Message msg = new Message();
		String str = null;
		Bundle bundle = new Bundle();
		byte errorType = response.getByte(Utils.STR_ERROR_CODE_TYPE);
		byte[] errorDetails = response.getByteArray(Utils.STR_ERROR_CODE_DETAIL);
		msg.what = 100;
		int error = (errorDetails[1] << 8) | ((int)errorDetails[0] & 0xFF);
		switch (error)
		{
			case 7:
				str = "illegal owner code";
				break;
			case 13:
				str = "wrong user ID";
				break;
			case 14:
				str = "wrong user PIN";
				break;
			case 17:
				str = "wrong eKey";
				break;
			case Utils.ERROR_DETAIL_WrongKDF:
				//*** ADDED FOR SECURITY INTEGRATION
				doHandshake();
				break;
			default:
				str = "undefined error";
				break;
		}

		bundle.putString("HANDLER_MESSAGE", str);
		msg.setData(bundle);
		mHandler.sendMessage(msg);
	}

	@Override
	public void onStopScan() {
		// TODO Auto-generated method stub
		setProgressBarIndeterminateVisibility(false);
		synchronized (object) {
			Log.d("MTLT_BLE", "calling NOTIFY");
			object.notify();
		}
	}

	@Override
	public void onGattConnected(int index) {
		// TODO Auto-generated method stub
    	endTime = System.currentTimeMillis();
    	diffTime = endTime - startTime;
        Log.i(TAG, "Connected done -- time: " + endTime + " diff = " + diffTime);
		mHandler.sendEmptyMessage(2);
		
	}

	@Override
	public void onGattDisconnected(int index) {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(3);
	}

	@Override
	public void onDiscoverServiceFailed() {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(8);
	}

	@Override
	public void onResponseControlRead() {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(1);
	}

	@Override
	public void onResponsePrimaryRead() {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(1);
	}

	@Override
	public void onGattError() {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(5);
	}

	@Override
	public void onRequestControlWrite() {
		// TODO Auto-generated method stub
		//perf();
	}
	
	private void perf()
	{
		return;
		/*
		//time_after = System.currentTimeMillis();
		time_after = System.nanoTime();
		long dif = time_after - time_before;
		Bundle bundle = new Bundle();
		Message msg = new Message();
		msg.what = 100;
		bundle.putString("HANDLER_MESSAGE", "time (nano) - " + dif);
		msg.setData(bundle);
		mHandler.sendMessage(msg);
		*/
	}

	@Override
	public void onResponseControlChanged() {
		// TODO Auto-generated method stub
		perf();
		//mHandler.sendEmptyMessage(1);
	}

	@Override
	public void onResponsePrimaryChanged() {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(1);
	}

	@Override
	public void onResponseSecondaryChanged() {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(0);
	}

	@Override
	public void onSendError() {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(7);
	}

	@Override
	public void onGetNewKeyResponse(Bundle response) {
		// TODO Auto-generated method stub
		eUserKey = response.getByteArray(Utils.STR_BLE_EKEY);
		lastRandom = response.getByteArray(Utils.STR_RANDOM_KEY);
		byte[] role = response.getByteArray(Utils.STR_ROLE);
		byte[] provider = response.getByteArray(Utils.STR_PROVIDER_ID);
		
		//*** ADDED FOR SECURITY INTEGRATION
		byte[] id = response.getByteArray(Utils.STR_BLE_ASSOCIATION_ID);
		SecUtils.setPersistentHandshakeId(currentDeviceName, id[0]);
		
		mHandler.sendEmptyMessage(6);
		Utils.addKey(this, this.lockName, this.userKeyName, eUserKey, this.newUserId);
	}

	@Override
	public void onKdfResponse(Bundle response) {
		// TODO Auto-generated method stub
		mHandler.sendEmptyMessage(6);
	}


	@Override
	public boolean isDeviceApproved(bleDevice device) {
		boolean realTest = false;
		if (!realTest)
			return true;
		if (Utils.hasKeyForLock(this, device.device.getName().getBytes()))
			return true;
		if (device.getLockState() == (byte)Utils.LOCK_STATE_UNINITIALIZED || device.getLockState() == (byte)Utils.LOCK_STATE_INITIALIZED_WITH_KEYS_PENDING)
			return true;
		else
			return false;
		//return name.equals("SBX-MTLT");
	}


	@Override
	public void onStatusResponse(Bundle response) {
		byte[] command = response.getByteArray(Utils.STR_COMMAND);
		byte[] valueLen = response.getByteArray(Utils.STR_STATUS_VALUE_LENGTH);
		byte[] value = response.getByteArray(Utils.STR_STATUS_VALUE);
		byte[] typeId = response.getByteArray(Utils.STR_STATUS_TYPE_ID);
	}


	@Override
	public void onExecutionError() {
		// TODO Auto-generated method stub
		
	}



	@Override
	public void onGetDeviceConfigResponse(Bundle response) {
		// TODO Auto-generated method stub
		boolean mute = response.getBoolean(Utils.STR_DEVICE_CONFIG_MUTE);
		boolean auto = response.getBoolean(Utils.STR_DEVICE_CONFIG_AUTO_LOCK);
		boolean locked = response.getBoolean(Utils.STR_DEVICE_STATE_LOCK_LOCKED);
		boolean closed = response.getBoolean(Utils.STR_DEVICE_STATE_DOOR_CLOSED);
		boolean charging = response.getBoolean(Utils.STR_DEVICE_STATE_LOCK_CHARGING);
		int b_state = response.getInt(Utils.STR_DEVICE_STATE_BATTERY_STATE);
		byte battery = response.getByte(Utils.STR_DEVICE_STATE_BATTERY_PERCENTAGE);
		
		String bat_state = (b_state == 0 ? "Low" : (b_state == 1 ? "Medium" : "High"));
//		String s =  " ENUM_CMD_GET_DEVICE_CONFIG_RESPONSE  --  Muted: " + mute + " Auto: " + auto + " lock locked: " + locked
//				+ " Door closed: " + closed + " Lock charging: " + charging
//				+ " battery state: " + bat_state + " batter % : " + battery;
		String s =  " UPDATE (" + update_count++ + ") ";
		if (p_mute != mute)
		{
			s +=  "Muted: " + mute;
			p_mute = mute;
		}
		if (p_auto != auto)
		{
			s +=  "Auto: " + auto;
			p_auto = auto;
		}
		if (p_locked != locked)
		{
			s +=  "locked: " + locked;
			p_locked = locked;
		}
		if (p_closed != closed)
		{
			s +=  "closed: " + closed;
			p_closed = closed;
		}
		if (p_charging != charging)
		{
			s +=  "charging: " + charging;
			p_charging = charging;
		}
		if (p_b_state != b_state)
		{
			s +=  "battery_state: " + b_state;
			p_b_state = b_state;
		}
		if (p_battery != battery)
		{
			s +=  "battery_%: " + battery;
			p_battery = battery;
		}
		
		
		//DeviceConn.setText(s);
		Bundle bundle = new Bundle();
		Message msg = new Message();
		msg.what = 101;

		bundle.putString("HANDLER_MESSAGE", s);
		msg.setData(bundle);
		mHandler.sendMessage(msg);
	}


	@Override
	public void onDiscoverServiceDone() {
		// TODO Auto-generated method stub
		//***ADDED FOR SECURITY INTEGRATION
		// need to call a method that tells if keys have been already exchanged and we need to start with KDF or perform ecdh
		byte id = SecUtils.getPersistentHandshakeId(currentDeviceName);

		if (id == -1) {
//			requestPublicKey();
			mHandler.sendEmptyMessage(50);
		}
		else {    	
//			doKDF();
			mHandler.sendEmptyMessage(51);
		}
	}


	@Override
	public void onCreateService(BluetoothLeService service) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void onGetKeysResponse(ArrayList<lockKeyData> lockKeysList) {
		Intent intent = new Intent(this, KeyList.class);
		intent.setAction(Intent.ACTION_VIEW);
		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		startActivity(intent);
		return;	
	}


	@Override
	public void onRecoverOwnerResponse(Bundle response) {
		lastRandom = response.getByteArray(Utils.STR_RANDOM_KEY);
		eKey = response.getByteArray(Utils.STR_BLE_EKEY);
		Utils.addKey(this, this.lockName, this.ownerKeyName, eKey, this.userId);
		
		//*** ADDED FOR SECURITY INTEGRATION
		byte[] id = response.getByteArray(Utils.STR_BLE_ASSOCIATION_ID);
		SecUtils.setPersistentHandshakeId(new String(newLockName), id[0]);
		
		
		mHandler.sendEmptyMessage(6);
		
	}
	
	private void testVerify()
	{
	    byte[] Signature = {(byte)0x30,(byte)0x46,(byte)0x02,(byte)0x21,(byte)0x00,(byte)0xe5,(byte)0x7e,(byte)0xc8,(byte)0x9b,(byte)0xf5,(byte)0x6c,(byte)0x92,(byte)0x11,(byte)0x38,(byte)0xc1,(byte)0xfc,(byte)0x56,(byte)0x07,(byte)0x8d,(byte)0x92,(byte)0x8d,(byte)0xec,(byte)0x7a,(byte)0xeb,(byte)0xe3,(byte)0x76,(byte)0x9b,(byte)0x8b,(byte)0x51,(byte)0x60,(byte)0x3d,(byte)0x53,(byte)0xaa,(byte)0xa6,(byte)0xf8,(byte)0xc0,(byte)0x65,(byte)0x02,(byte)0x21,(byte)0x00,(byte)0xb3,(byte)0x4f,(byte)0x93,(byte)0xf7,(byte)0x6d,(byte)0x20,(byte)0xdf,(byte)0x55,(byte)0x62,(byte)0x6a,(byte)0xd1,(byte)0xd6,(byte)0xbe,(byte)0x96,(byte)0x6e,(byte)0x1a,(byte)0x3b,(byte)0x4b,(byte)0x3c,(byte)0x6b,(byte)0x19,(byte)0xe0,(byte)0x9c,(byte)0xd1,(byte)0xb2,(byte)0xce,(byte)0x23,(byte)0xe8,(byte)0x8c,(byte)0x10,(byte)0x7f,(byte)0x92};
	    final byte[] source = {0};
	    
    	try {
    		PublicKey remoteKey = null;
    		byte[] remoteKeyBytes = {(byte)0x68,(byte)0x05,(byte)0x28,(byte)0x10,(byte)0x62,(byte)0x17,(byte)0x28,(byte)0xc7,(byte)0xd7,(byte)0xcd,(byte)0x9d,(byte)0xcc,(byte)0x14,(byte)0xe6,(byte)0x04,(byte)0x16,(byte)0xad,(byte)0x08,(byte)0x95,(byte)0xc6,(byte)0x19,(byte)0xa1,(byte)0x41,(byte)0xa4,(byte)0xd6,(byte)0xe0,(byte)0x46,(byte)0x1d,(byte)0x13,(byte)0xb5,(byte)0x0f,(byte)0x40,(byte)0x32,(byte)0xfa,(byte)0x5c,(byte)0xd5,(byte)0x6b,(byte)0x1e,(byte)0xd9,(byte)0x1e,(byte)0xd6,(byte)0x3d,(byte)0x3e,(byte)0xd5,(byte)0x12,(byte)0x0d,(byte)0x41,(byte)0x1f,(byte)0x27,(byte)0x21,(byte)0xc7,(byte)0xf3,(byte)0x63,(byte)0xc1,(byte)0x08,(byte)0xe3,(byte)0x8e,(byte)0x69,(byte)0xb8,(byte)0x65,(byte)0xe8,(byte)0xb8,(byte)0xe7,(byte)0x68};

    		SecUtils.setRemoteAESPublicKey(remoteKeyBytes);
			//key = Crypto.setOtherPublicKey(remoteKey);
			remoteKey = SecUtils.getRemoteECDSAPublicKey();

    		Crypto crypto = Crypto.getInstance();
			boolean b = crypto.verify(this, remoteKey, source, Signature);
			if (b)
				Toast.makeText(this, "Verification SUCCEEDED", Toast.LENGTH_SHORT).show();
			else
				Toast.makeText(this, "Verification FAILED", Toast.LENGTH_SHORT).show();
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
	
	private byte[] lastIV = null;



	@Override
	public void onBleReady2Comm(Bundle response) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void onGetKeysLeft(int keysLeft) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void onGetCommVersionResponse(Bundle response) {
		byte[] version = response.getByteArray(Utils.STR_COMMUNICATION_VERSION);
		
		Log.d(TAG, "Comm version " + new String(version));
		tvOutput.setText("Comm version " + new String(version));
	}


	@Override
	public void onGetDeviceInfoResponse(Bundle response) {
		byte[] version = response.getByteArray(Utils.STR_DEVICE_CODE_VERSION);
		
		byte[] model = response.getByteArray(Utils.STR_DEVICE_CODE_VERSION);

//Utils.STR_DEVICE_ID Utils.STR_DEVICE_MODEL, Utils.STR_DEVICE_CODE_VERSION, Utils.STR_DEVICE_UPDATE_STATUS
        byte[] id = response.getByteArray(Utils.STR_DEVICE_ID);
        String deviceId = new String(id);
//        byte b_model = response.getByte(Utils.STR_DEVICE_MODEL);
        byte[] ba_model = null;
        String deviceModel = "unknown";
        ByteArrayBuffer tmp = null;
        int count = 0;

//        if (b_model == 0) {
            ba_model = response.getByteArray(Utils.STR_DEVICE_MODEL);
            if (ba_model != null) {
                count = 0;
                for (int i=0; i<ba_model.length; i++)
                    if (ba_model[i] != 0)
                        count++;
                    else
                        break;
                tmp = new ByteArrayBuffer(count);
                tmp.append(ba_model, 0, count);
                deviceModel = new String(tmp.buffer());
            }
//        } else {
//            deviceModel = "" + (char)b_model;
//        }
        byte[] ba_codeVersion = response.getByteArray(Utils.STR_DEVICE_CODE_VERSION);
        count = 0;
        for (int i=0; i<ba_codeVersion.length; i++)
            if (ba_codeVersion[i] != 0)
                count++;
            else
                break;
        tmp = new ByteArrayBuffer(count);
        tmp.append(ba_codeVersion, 0, count);
        String codeVersion = new String(tmp.buffer());

        byte[] updateStatus = response.getByteArray(Utils.STR_DEVICE_UPDATE_STATUS);
        String str = deviceModel + " " + codeVersion + " status: " +
                Utils.decToHex(updateStatus[0]) + ":" + Utils.decToHex(updateStatus[1]) + ":" +
                Utils.decToHex(updateStatus[2]) + ":" + Utils.decToHex(updateStatus[3]);

        Log.d(TAG, "Code version " + str);

//		tvOutput.setText("Device info " + info);
        Message msg = new Message();
        Bundle bundle = new Bundle();
        msg.what = 100;

        bundle.putString("HANDLER_MESSAGE", str);
        msg.setData(bundle);
        mHandler.sendMessage(msg);
	}


	@Override
	public void onTimerExpired(int command) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDownloadParamsResponse(Bundle response) {
		byte[] start = response.getByteArray(Utils.STR_PREFERRED_START_ADDRESS);
		byte[] size = response.getByteArray(Utils.STR_PREFERRED_CHUNK_SIZE);
		byte[] FotaIv = response.getByteArray(Utils.STR_IV);
		SecUtils.setNextIv2(FotaIv);
		preferredStart = Utils.toInt(start);
		preferredSize = Utils.toInt(size);
		mHandler.sendEmptyMessage(Utils.ENUM_CMD_OTA_UPDATE);
		return;
	}

	@Override
	public void onDownloadCompleteResponse(Bundle response) {
		byte status = response.getByte(Utils.STR_DOWNLOAD_COMPLETE_STATUS);
		byte content = response.getByte(Utils.STR_DP_CONTENT);
		Message msg = new Message();
		msg.what = Utils.ENUM_CMD_DOWNLOAD_COMPLETE_RESPONSE;
		msg.arg1 = status;
		msg.arg2 = content;
		mHandler.sendMessage(msg);
	}

	@Override
	public void onInstallStatus(Bundle response) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onDownloadChunkStatus(Bundle response) {
		byte status = response.getByte(Utils.STR_DOWNLOAD_CHUNK_STATUS);
		byte[] num = response.getByteArray(Utils.STR_CHUNK_NUM);
		int chunkNum = Utils.toInt(num);
		Message msg = new Message();
		msg.what = Utils.ENUM_CMD_DOWNLOAD_CHUNK_STATUS;
		msg.arg2 = chunkNum;
		msg.arg1 = status;
		mHandler.sendMessage(msg);
	}

	@Override
	public void onGetErrorsResponse(Bundle response) {
		// TODO Auto-generated method stub
		byte[] data = response.getByteArray(Utils.STR_GET_ERRORS_RESPONSE_DATA);
		getErrors.insertToBuffer(data);
	}

    @Override
    public void onGetIvResponse(Bundle response) {
        byte[] iv = response.getByteArray(Utils.STR_IV);
        if (iv == null)
            return;
        SecUtils.setNextIv2(iv);
        mHandler.sendEmptyMessage(Utils.ENUM_CMD_GET_IV_RESPONSE);
    }


}
