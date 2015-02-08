package com.multlock.key;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.util.Log;


import com.multlock.key.BleUtils.bleDevice;

/**
 * Service for managing connection and data communication with a GATT server hosted on a
 * given Bluetooth LE device. Here we scan only for known (UUID) devices.
 */
public class BluetoothLeService extends Service {
    private final static String TAG = BluetoothLeService.class.getSimpleName();
    
    private BleUtils ble;
    
    private Binder mBinder; 
    
    private BleInterface iFace = null;
    
    //IBinder mBinder = new LocalBinder();

    @Override
    public IBinder onBind(Intent intent) {
     return mBinder;
    }
    
    
    public class Binder extends android.os.Binder {
        public BluetoothLeService getService() {
            return BluetoothLeService.this;
        }
    }


    private Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
        	return;
        }
    };
    
 
	@Override
	public void onCreate() {
		Log.i(TAG, "BluetoothLeService - onCreate");
		ble = new BleUtils();
        mBinder = new Binder();

		iFace = new serviceBleInterface(this);
		ble.init(this, mHandler, iFace);
		
		iFace.onCreateService(this);
		
		ble.autoScan(2500, 2500);
	}

	@Override
	public void onDestroy() {
		ble.disconnect(0);
		super.onDestroy();
		
	}


    @Override
    public boolean onUnbind(Intent intent) {
        return super.onUnbind(intent);
    } 
    
    public BleUtils getBle()
    {
    	return ble;
    }
    
    public void setInterface(BleInterface iface)
    {
    	iFace = iface;
    	this.ble.setBleInterface(iface);
    }


}
