package com.multlock.key;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Debug;
import android.util.Log;

public class StartupIntentReceiver extends BroadcastReceiver
{
	
	private final static String TAG = BluetoothLeService.class.getSimpleName();
	
@Override
	public void onReceive(Context context, Intent intent) {
		Log.i(TAG, "Broadcast Receiver - starting Service");
		//Debug.waitForDebugger();
		if (Utils.getServiceOn(context))
			Utils.startBleService(context);
	}
}
