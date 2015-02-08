package com.multlock.key;

import java.util.ArrayList;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import com.multlock.key.BleUtils.bleDevice;
import com.multlock.key.BleUtils.lockKeyData;

public class serviceBleInterface implements BleInterface {

    	private final static String TAG = BluetoothLeService.class.getSimpleName();
    	
    	private Context context = null;
    	
    	public serviceBleInterface(Context context) {
    		this.context = context;
    	}
    	
    	public serviceBleInterface() {
    		//
    	}

    
		@Override
		public void onSendPublicKeyResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onHandshakeResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onSetOwnerResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onLastRequestSuccess() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onRequestSuccess(Bundle response) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onRequestError(Bundle response) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onGattConnected(int index) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onGattDisconnected(int index) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onDiscoverServiceFailed() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onResponseControlRead() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onResponsePrimaryRead() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onGattError() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onRequestControlWrite() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onResponseControlChanged() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onResponsePrimaryChanged() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onResponseSecondaryChanged() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onSendError() {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onGetNewKeyResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public void onKdfResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}
	
		@Override
		public boolean isDeviceApproved(bleDevice device) {
			// TODO Auto-generated method stub
			return true;
		}
	
		@Override
		public void onStatusResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}
		
		private static final int DIALOG_ALERT = 10;
	
		@Override
		public void onLeScanDeviceFound(bleDevice btDevice) {
			// TODO Auto-generated method stub
			Log.i(TAG, "BluetoothLeService - onLeScanDeviceFound");
			
			if (context == null)
				return;
			
			Intent intent = new Intent(context, SecPage.class);
			intent.setAction(Intent.ACTION_VIEW);
			intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
	
			//context.startActivity(intent);
			
		}
	
		@Override
		public void onStopScan() {
			// TODO Auto-generated method stub
			Log.i(TAG, "onStopScan in SERVICE - called");
		}

		@Override
		public void onExecutionError() {
			// TODO Auto-generated method stub
			
		}


		@Override
		public void onGetDeviceConfigResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onDiscoverServiceDone() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onCreateService(BluetoothLeService service) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetKeysResponse(ArrayList<lockKeyData> lockKeysList) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onRecoverOwnerResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}

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
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetDeviceInfoResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onTimerExpired(int command) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onDownloadParamsResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onDownloadCompleteResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onInstallStatus(Bundle response) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onDownloadChunkStatus(Bundle response) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void onGetErrorsResponse(Bundle response) {
			// TODO Auto-generated method stub
			
		}

    @Override
    public void onGetIvResponse(Bundle response) {

    }


}
