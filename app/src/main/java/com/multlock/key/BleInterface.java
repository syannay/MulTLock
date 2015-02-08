package com.multlock.key;

import java.util.ArrayList;
import java.util.UUID;

import com.multlock.key.BleUtils.bleDevice;
import com.multlock.key.BleUtils.lockKeyData;

import android.os.Bundle;

public interface BleInterface {
	
	//sent on each BLE device found by scan
	public void onLeScanDeviceFound(bleDevice btDevice);
	
	//called when scan stopped
	public void onStopScan();
	
	//called on response to public key exchange between lock and mobile
	public void onSendPublicKeyResponse(Bundle response);

	//called when handshake done
	public void onHandshakeResponse(Bundle response);
	
	//called in response to setOwner
	public void onSetOwnerResponse(Bundle response);
	
	//called when last request succeeded (implicit call)
	public void onLastRequestSuccess();
	
	//called when command succeeded - command defined in response explicitly
	public void onRequestSuccess(Bundle response);
	
	//called when command failed - command defined in response explicitly
	public void onRequestError(Bundle response);

	//called when GATT connected
	public void onGattConnected(int index);

	//called when GATT disconnected
	public void onGattDisconnected(int index);

	//called when failed to find requested services in connected device
	public void onDiscoverServiceFailed();

	//called when we get a response to control service read
	public void onResponseControlRead();

	//called after we read primary characteristic value
	public void onResponsePrimaryRead();

	//called on GATT error
	public void onGattError();

	//called on request control write action to lock
	public void onRequestControlWrite();

	//called on notification on Control characteristic change
	public void onResponseControlChanged();

	//called on notification on Primary payload characteristic change
	public void onResponsePrimaryChanged();

	//called on notification on Secondary payload characteristic change
	public void onResponseSecondaryChanged();
	
	//called on error sending data to lock
	public void onSendError();
	
	//called in response to GetKey
	public void onGetNewKeyResponse(Bundle response);
	
	//called in response to KDF
	public void onKdfResponse(Bundle response);
	
	//called when a new device found on scan to filter illegal devices
	public boolean isDeviceApproved(bleDevice device);
	
	//called when an asynch status sent from the device
	public void onStatusResponse(Bundle response);
	
	//called when an asynch status sent from the device
	public void onExecutionError();
	
	//called when an list of keys sent from the device
	public void onGetKeysResponse(ArrayList<lockKeyData> lockKeysList);
	
	//called when device config returned from the device
	public void onGetDeviceConfigResponse(Bundle response);
	
	//called when done discovering services
	public void onDiscoverServiceDone();
	
	//called when service create called
	public void onCreateService(BluetoothLeService service);
	
	//called when recover owner returns
	public void onRecoverOwnerResponse(Bundle response);
	
	//called when BleUtils is ready to get commands
	public void onBleReady2Comm(Bundle response);
	
	//called when getKeys return with partial list of keys
	public void  onGetKeysLeft(int keysLeft);
	
	//called when GetCommVersion returns
	public void  onGetCommVersionResponse(Bundle response);
	
	//called when GetDeviceInfo returns
	public void  onGetDeviceInfoResponse(Bundle response);

	//called when timer expires without getting a response from the lock
	public void  onTimerExpired(int command);
	
	//called when DownloadParamsResponse returns
	public void onDownloadParamsResponse(Bundle response);
	
	//called when DownloadCompleteResponse returns
	public void onDownloadCompleteResponse(Bundle response);
	
	//called when onInstallStatus returns
	public void onInstallStatus(Bundle response);
	
	//called when onDownloadChunkStatus returns
	public void onDownloadChunkStatus(Bundle response);
	
	//called when onGetErrorsResponse returns
	public void onGetErrorsResponse(Bundle response);

    //called when onGetIvResponse returns
    public void onGetIvResponse(Bundle response);
	
}
