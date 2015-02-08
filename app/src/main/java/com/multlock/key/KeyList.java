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



public class KeyList extends Activity {
	
	private static int selectedItem = 0;
	
	private static BleInterface ble_int;
	
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	    setContentView(R.layout.keylist);
	    
	    final ListView listview = (ListView) findViewById(R.id.listView1);
	    
	    boolean fake = false;
	    
	    final ArrayList<String> list = new ArrayList<String>();
	    
	    MainActivity.skipDisconnect = false;

	    
	    if (fake) {
	   
		    String[] values = new String[] { "Android", "iPhone", "WindowsMobile",
		            "Blackberry", "WebOS", "Ubuntu", "Windows7", "Max OS X",
		            "Linux", "OS/2", "Ubuntu", "Windows7", "Max OS X", "Linux",
		            "OS/2", "Ubuntu", "Windows7", "Max OS X", "Linux", "OS/2",
		            "Android", "iPhone", "WindowsMobile" };

	        for (int i = 0; i < values.length; ++i) {
	          list.add(values[i]);
	        }
	    } else {
	        
		    for (int i = 0; i < BleUtils.lockKeysList.size(); ++i) {
		    	String name = new String (BleUtils.lockKeysList.get(i).user);
		    	name += "** role = " + BleUtils.lockKeysList.get(i).role + " state = " + BleUtils.lockKeysList.get(i).state;
		    	list.add(name);
		    }
	    }
		
	    final StableArrayAdapter adapter = new StableArrayAdapter(this,
	        android.R.layout.simple_list_item_1, list);
	    listview.setAdapter((ListAdapter) adapter);

	    listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {

	      @Override
	      public void onItemClick(AdapterView<?> parent, final View view,
	          int position, long id) {
	    	  
	    	  selectedItem = position;
	    	  
	    	  Toast.makeText(view.getContext(), "clicked on item " + position, Toast.LENGTH_SHORT).show();

	      }

	    });
	}
	    
    private class StableArrayAdapter extends ArrayAdapter<String> {

        HashMap<String, Integer> mIdMap = new HashMap<String, Integer>();

        public StableArrayAdapter(Context context, int textViewResourceId,
            List<String> objects) {
          super(context, textViewResourceId, objects);
          for (int i = 0; i < objects.size(); ++i) {
            mIdMap.put(objects.get(i), i);
          }
        }

        @Override
        public long getItemId(int position) {
          String item = getItem(position);
          return mIdMap.get(item);
        }

        @Override
        public boolean hasStableIds() {
          return true;
        }

	  }
    
    public void onDelete(View view)
    {
    	//BleUtils.lockKeysList.get(selectedItem).user;
    	BleUtils ble = MainActivity.ble;
    	
    	if (!ble.IsConnected())
    	{
    		Toast.makeText(view.getContext(), "Not Connected", Toast.LENGTH_SHORT).show();
    		return;
    	}
    	
    	Bundle params = new Bundle();

    	boolean useAdmin = false;

        params.putByteArray(Utils.STR_USER_ID, BleUtils.lockKeysList.get(selectedItem).user);
        params.putByteArray(Utils.STR_ADMIN_CODE, MainActivity.newCode);
        params.putByteArray(Utils.STR_APP_ID, MainActivity.appId);


        //params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(MainActivity.lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_REVOKE_KEY);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, MainActivity.mHandler, (BleInterface)ble_int);
        
        ble_task.execute(params);

    }
    
    public void onEnable(View view)
    {
    	//BleUtils.lockKeysList.get(selectedItem).user;
    	BleUtils ble = MainActivity.ble;
    	
    	if (!ble.IsConnected())
    	{
    		Toast.makeText(view.getContext(), "Not Connected", Toast.LENGTH_SHORT).show();
    		return;
    	}
    	
    	Bundle params = new Bundle();

    	boolean useAdmin = false;

        params.putByteArray(Utils.STR_USER_ID, BleUtils.lockKeysList.get(selectedItem).user);
        params.putByteArray(Utils.STR_ADMIN_CODE, MainActivity.newCode);
        params.putByteArray(Utils.STR_APP_ID, MainActivity.appId);


        //params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(MainActivity.lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_ENABLE_KEY);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, (Handler)null, (BleInterface)ble_int);
        
        ble_task.execute(params);
    }
    
    public void onDisable(View view)
    {
    	//BleUtils.lockKeysList.get(selectedItem).user;
    	BleUtils ble = MainActivity.ble;
    	
    	if (!ble.IsConnected())
    	{
    		Toast.makeText(view.getContext(), "Not Connected", Toast.LENGTH_SHORT).show();
    		return;
    	}
    	
    	Bundle params = new Bundle();

    	boolean useAdmin = false;

        params.putByteArray(Utils.STR_USER_ID, BleUtils.lockKeysList.get(selectedItem).user);
        params.putByteArray(Utils.STR_ADMIN_CODE, MainActivity.newCode);
        params.putByteArray(Utils.STR_APP_ID, MainActivity.appId);


        //params.putByteArray(Utils.STR_APP_ID, appId);
        params.putByteArray(Utils.STR_RANDOM_KEY, SecUtils.manipulateRandom(MainActivity.lastRandom));
        
        params.putByte(Utils.STR_COMMAND, Utils.ENUM_CMD_DISABLE_KEY);
        
        BleUtils ble_task = new BleUtils();
        
        ble_task.init(this, (Handler)null, (BleInterface)ble_int);
        
        ble_task.execute(params);
    }
}

		

	    
