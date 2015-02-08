package com.multlock.key;

import java.util.ArrayList;
import java.util.HashMap;
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
import android.graphics.Color;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.util.Log;
import android.util.SparseArray;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnLongClickListener;
import android.widget.AbsListView;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import org.apache.http.util.ByteArrayBuffer;

import com.multlock.key.BleUtils.bleDevice;
import com.multlock.key.BleUtils.lockKeyData;



public class getErrors extends Activity {
	
	private static BleInterface ble_int;
	
	private static TextView text;
	
	private static ByteArrayBuffer buffer = new ByteArrayBuffer(10000);
	
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	    setContentView(R.layout.get_errors);
	    
	    text = (TextView) findViewById(R.id.editText1);
	    
	    text.setText(new String(buffer.buffer()));
	    	    
//	    text.setText("hello world");
	}
	
	public static void insertToBuffer(byte[] data)
	{
		buffer.append(data, 0, data.length);
	}
	    
    
    public void onClear(View view)
    {
    	text.setText("");
    }
    
    public void onClose(View view)
    {
    	finish();
    }

}

		

	    
