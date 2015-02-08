package com.multlock.key;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.json.JSONObject;

import android.util.Log;

public class commTest {
	
	private static boolean UseSSL = false;
	   
		public static JSONObject getJSON(String httpget)//retrieving the JSON from server
		{
//			Log.d(TAG, "getJSON was called");
			JSONObject json = null;
			try 
			{
				HttpGet httpGet = new HttpGet();
				
				HttpParams httpParameters = new BasicHttpParams();
				// Set the timeout in milliseconds until a connection is established.
				// The default value is zero, that means the timeout is not used. 
				int timeoutConnection = 3000;
				HttpConnectionParams.setConnectionTimeout(httpParameters, timeoutConnection);
				// Set the default socket timeout (SO_TIMEOUT) 
				// in milliseconds which is the timeout for waiting for data.
				int timeoutSocket = 3000;
				HttpConnectionParams.setSoTimeout(httpParameters, timeoutSocket);
				
				DefaultHttpClient client=null;
				httpGet.setURI(new URI(httpget));
				if (UseSSL == true)
				{
					HttpClient Client = new DefaultHttpClient();
					HostnameVerifier hostnameVerifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
					SchemeRegistry registry = new SchemeRegistry();
					
					SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();
					socketFactory.setHostnameVerifier((X509HostnameVerifier) hostnameVerifier);
					registry.register(new Scheme("https", socketFactory, 443));
					SingleClientConnManager mgr = new SingleClientConnManager(Client.getParams(), registry);
					//client = new DefaultHttpClient(mgr, Client.getParams());
					client = new DefaultHttpClient(mgr, httpParameters);
					// Set verifier      
					HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
				}
				else 
				{
					client = new DefaultHttpClient(httpParameters);
				}
				
				//code to avoid the socket error
				if (Integer.valueOf(android.os.Build.VERSION.SDK_INT) >= 9) {
				    try {
				        // StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.LAX);
				           Class<?> strictModeClass = Class.forName("android.os.StrictMode", true, Thread.currentThread()
				                        .getContextClassLoader());
				           Class<?> threadPolicyClass = Class.forName("android.os.StrictMode$ThreadPolicy", true, Thread.currentThread()
				                        .getContextClassLoader());
				           //Field laxField = context.threadPolicyClass.getField("LAX");
				           //Method setThreadPolicyMethod = strictModeClass.getMethod("setThreadPolicy", threadPolicyClass);
				                //setThreadPolicyMethod.invoke(strictModeClass, laxField.get(null));
				    } 
				    catch (Exception e) { }
				}			
				// end of protection code
				//long unixTime1 = System.currentTimeMillis();
				
				HttpResponse response = client.execute(httpGet);
				//long unixTime2 = System.currentTimeMillis();
				//Log.i("time diff (milli) before and after server: ", Long.toString(unixTime2-unixTime1));
				HttpEntity entity = response.getEntity();
				if (entity != null)
				{
	                InputStream instream = entity.getContent();
	                //json = new JSONObject(convertStreamToString(instream));
				}
			} 
			catch (URISyntaxException e1) 
			{
				// TODO Auto-generated catch block
				Log.e("Socket error", "URISyntaxException");
				e1.printStackTrace();
				return null;
			}
		    catch (ClientProtocolException e)
			{
		    	Log.e("Socket error", "ClientProtocolException");
				e.printStackTrace();
				return null;
			} 
			catch (IOException e) 
			{
				Log.e("Socket error", "IOException");
				e.printStackTrace();
				Log.e("Dial2Web",e.getMessage());
				return null;
			} 
			catch (Exception e)
			{
				Log.e("Socket error", "general exception");
				e.printStackTrace();
				return null;
			}
//			Log.d(TAG, "getJSON was ended successfully");
			return json;
		}



}
