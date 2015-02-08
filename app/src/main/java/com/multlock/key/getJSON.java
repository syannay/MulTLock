/*
******************************************************
* (c) COPYRIGHT 2013 Dial2Web.  All Rights Reserved. *
******************************************************
*/
package com.multlock.key;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;

import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

public class getJSON extends AsyncTask<String, Void, String[]> {
	Context context;

	
	public getJSON(Context context)
	{
		this.context = context;
	}
	
	
	@Override
	protected  void onPreExecute()
	{
		Log.d("onPreExecutive","called");
		//code to avoid the socket error
		if (Integer.valueOf(android.os.Build.VERSION.SDK_INT) >= 9) {
		    try {
		        // StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.LAX);
		           Class<?> strictModeClass = Class.forName("android.os.StrictMode", true, Thread.currentThread()
		                        .getContextClassLoader());
		           Class<?> threadPolicyClass = Class.forName("android.os.StrictMode$ThreadPolicy", true, Thread.currentThread()
		                        .getContextClassLoader());
		           Field laxField = threadPolicyClass.getField("LAX");
		           Method setThreadPolicyMethod = strictModeClass.getMethod("setThreadPolicy", threadPolicyClass);
		                setThreadPolicyMethod.invoke(strictModeClass, laxField.get(null));
		    } 
		    catch (Exception e) { }
		}			
		// end of protection code
	}


	@Override
	protected String[] doInBackground(String... params) {
		// TODO Auto-generated method stub

			try 
			{
				
				String[] rc = new String[2];
				
				String jsonStr = params[0];
				JSONObject json = commTest.getJSON(jsonStr);

				//Toast.makeText(context, json.getString("name"), Toast.LENGTH_SHORT).show();
				if (json != null) 
				{
					String str = json.getString("success");
					String method = json.getString("method");
					rc[1] = method;
					
					if (str.compareTo("true") != 0)
					{
						Log.e("Async", "Inside doInBackground: json object returned Success==false");
						rc[0] = "fail";
						//rc[1] = "keys";
						return rc;
					}
					rc[0] = "success";
					//String method = json.getString("method");
				} //if (json != null)
				else
				{
					Log.e("Async", "Inside Dialout listener: json object is null");
					//Toast.makeText(context, "cannot convert number to URL - server returned null", Toast.LENGTH_SHORT).show();
				} 
			}
			catch (JSONException e) 
			{
				Log.e("Async", "Inside Dialout listener: catch json exception");
				e.printStackTrace();
			} 
			catch (Exception e) 
			{
				Log.e("Async", "Inside Dialout listener: catch general exception");
				e.printStackTrace();
			}

			return null;
	}
	
	@Override
    protected void onPostExecute(final String[] result)
    {
    	
    }

}


