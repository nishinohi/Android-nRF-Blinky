/*
 * Copyright (c) 2018, Nordic Semiconductor
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package no.nordicsemi.android.blinky.profile;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.util.UUID;

import no.nordicsemi.android.ble.data.Data;
import no.nordicsemi.android.ble.livedata.ObservableBleManager;
import no.nordicsemi.android.blinky.profile.callback.BlinkyButtonDataCallback;
import no.nordicsemi.android.blinky.profile.callback.BlinkyLedDataCallback;
import no.nordicsemi.android.blinky.profile.callback.FruityEncryptDataCallback;
import no.nordicsemi.android.blinky.profile.data.BlinkyLED;
import no.nordicsemi.android.blinky.profile.packet.FruityPacket;
import no.nordicsemi.android.log.LogContract;
import no.nordicsemi.android.log.LogSession;
import no.nordicsemi.android.log.Logger;

public class BlinkyManager extends ObservableBleManager {
    /**
     * MeshAccessService UUID
     */
    public final static UUID MA_UUID_SERVICE = UUID.fromString("00000001-acce-423c-93fd-0c07a0051858");
    /**
     * RX characteristic UUID (use for send packet to peripheral)
     */
    public final static UUID MA_UUID_RX_CHAR = UUID.fromString("00000002-acce-423c-93fd-0c07a0051858");
    /**
     * TX characteristic UUID (use for receive packet from peripheral)
     */
    public final static UUID MA_UUID_TX_CHAR = UUID.fromString("00000003-acce-423c-93fd-0c07a0051858");
    /**
     * Nordic Blinky Service UUID.
     */
    public final static UUID LBS_UUID_SERVICE = UUID.fromString("00001523-1212-efde-1523-785feabcd123");
    /**
     * BUTTON characteristic UUID.
     */
    private final static UUID LBS_UUID_BUTTON_CHAR = UUID.fromString("00001524-1212-efde-1523-785feabcd123");
    /**
     * LED characteristic UUID.
     */
    private final static UUID LBS_UUID_LED_CHAR = UUID.fromString("00001525-1212-efde-1523-785feabcd123");

    private final MutableLiveData<Boolean> ledState = new MutableLiveData<>();
    private final MutableLiveData<Boolean> buttonState = new MutableLiveData<>();

    private BluetoothGattCharacteristic buttonCharacteristic, ledCharacteristic;
    private BluetoothGattCharacteristic maTxCharacteristic, maRxCharacteristic;
    private LogSession logSession;
    private boolean supported;
    private boolean ledOn;

    public BlinkyManager(@NonNull final Context context) {
        super(context);
    }

    public final LiveData<Boolean> getLedState() {
        return ledState;
    }

    public final LiveData<Boolean> getButtonState() {
        return buttonState;
    }

    @NonNull
    @Override
    protected BleManagerGattCallback getGattCallback() {
        return new BlinkyBleManagerGattCallback();
    }

    /**
     * Sets the log session to be used for low level logging.
     *
     * @param session the session, or null, if nRF Logger is not installed.
     */
    public void setLogger(@Nullable final LogSession session) {
        logSession = session;
    }

    @Override
    public void log(final int priority, @NonNull final String message) {
        // The priority is a Log.X constant, while the Logger accepts it's log levels.
        Logger.log(logSession, LogContract.Log.Level.fromPriority(priority), message);
    }

    @Override
    protected boolean shouldClearCacheWhenDisconnected() {
        return !supported;
    }

	/**
	 * The Button callback will be notified when a notification from Button characteristic
	 * has been received, or its data was read.
	 * <p>
	 * If the data received are valid (single byte equal to 0x00 or 0x01), the
	 * {@link BlinkyButtonDataCallback#onButtonStateChanged} will be called.
	 * Otherwise, the {@link BlinkyButtonDataCallback#onInvalidDataReceived(BluetoothDevice, Data)}
	 * will be called with the data received.
	 */
	private	final BlinkyButtonDataCallback buttonCallback = new BlinkyButtonDataCallback() {
		@Override
		public void onButtonStateChanged(@NonNull final BluetoothDevice device,
										 final boolean pressed) {
			log(LogContract.Log.Level.APPLICATION, "Button " + (pressed ? "pressed" : "released"));
			buttonState.setValue(pressed);
		}

        @Override
        public void onInvalidDataReceived(@NonNull final BluetoothDevice device,
                                          @NonNull final Data data) {
            log(Log.WARN, "Invalid data received: " + data);
        }
    };

    /**
     * The LED callback will be notified when the LED state was read or sent to the target device.
     * <p>
     * This callback implements both {@link no.nordicsemi.android.ble.callback.DataReceivedCallback}
     * and {@link no.nordicsemi.android.ble.callback.DataSentCallback} and calls the same
     * method on success.
     * <p>
     * If the data received were invalid, the
     * {@link BlinkyLedDataCallback#onInvalidDataReceived(BluetoothDevice, Data)} will be
     * called.
     */
    private final BlinkyLedDataCallback ledCallback = new BlinkyLedDataCallback() {
        @Override
        public void onLedStateChanged(@NonNull final BluetoothDevice device,
                                      final boolean on) {
            ledOn = on;
            log(LogContract.Log.Level.APPLICATION, "LED " + (on ? "ON" : "OFF"));
            ledState.setValue(on);
        }

        @Override
        public void onInvalidDataReceived(@NonNull final BluetoothDevice device,
                                          @NonNull final Data data) {
            // Data can only invalid if we read them. We assume the app always sends correct data.
            log(Log.WARN, "Invalid data received: " + data);
        }
    };

    private final FruityEncryptDataCallback fruityEncryptDataCallback = new FruityEncryptDataCallback();

    /**
     * BluetoothGatt callbacks object.
     */
    private class BlinkyBleManagerGattCallback extends BleManagerGattCallback {
        @Override
        protected void initialize() {
//			setNotificationCallback(buttonCharacteristic).with(buttonCallback);
//			readCharacteristic(ledCharacteristic).with(ledCallback).enqueue();
//			readCharacteristic(buttonCharacteristic).with(buttonCallback).enqueue();
//			enableNotifications(buttonCharacteristic).enqueue();
            setNotificationCallback(maTxCharacteristic).with(fruityEncryptDataCallback);
            enableNotifications(maTxCharacteristic).enqueue();
            startHandshake();
        }

        private void startHandshake() {
            // stub
            FruityPacket.ConnPacketEncryptCustomStart packet = new FruityPacket.ConnPacketEncryptCustomStart();
            packet.header.messageType = FruityPacket.MessageType.ENCRYPT_CUSTOM_START;
            packet.header.sender = 259; // TODO
            packet.header.receiver = 0; // Virtual Partner ID
            packet.version = 1;
            packet.fmKeyId = FruityPacket.FmKeyId.NODE;
            packet.tunnelType = 0;
            packet.reserved = 0;
            Data encryptCustomStart = new Data(FruityPacket.createEncryptCustomStartPacket(packet));
            writeCharacteristic(maRxCharacteristic, encryptCustomStart).with(ledCallback).enqueue();
        }

        private void createPacket(FruityPacket.ConnPacketEncryptCustomStart packet, int dataLength, boolean reliable) {
            FruityPacket.BaseConnectionSendData sendData = new FruityPacket.BaseConnectionSendData();
            sendData.characteristicHandle = 0; // not need to set
            sendData.dataLength = dataLength;
            sendData.deliveryOption = reliable ? FruityPacket.DeliveryOption.WRITE_REQ : FruityPacket.DeliveryOption.WRITE_CMD;
        }

        @Override
        public boolean isRequiredServiceSupported(@NonNull final BluetoothGatt gatt) {
            final BluetoothGattService maService = gatt.getService(MA_UUID_SERVICE);
            if (maService != null) {
                maTxCharacteristic = maService.getCharacteristic(MA_UUID_TX_CHAR);
                maRxCharacteristic = maService.getCharacteristic(MA_UUID_RX_CHAR);
            }
            boolean rxWriteRequest = false;
            if (maRxCharacteristic != null) {
                final int proper = maRxCharacteristic.getProperties();
                rxWriteRequest = (proper & BluetoothGattCharacteristic.PROPERTY_WRITE) > 0;
            }
            final BluetoothGattService service = gatt.getService(LBS_UUID_SERVICE);
            if (service != null) {
                buttonCharacteristic = service.getCharacteristic(LBS_UUID_BUTTON_CHAR);
                ledCharacteristic = service.getCharacteristic(LBS_UUID_LED_CHAR);
            }

            boolean writeRequest = false;
            if (ledCharacteristic != null) {
                final int rxProperties = ledCharacteristic.getProperties();
                writeRequest = (rxProperties & BluetoothGattCharacteristic.PROPERTY_WRITE) > 0;
            }

            supported = maRxCharacteristic != null && maTxCharacteristic != null && rxWriteRequest;
//			supported = buttonCharacteristic != null && ledCharacteristic != null && writeRequest;
            return supported;
        }

        @Override
        protected void onDeviceDisconnected() {
            buttonCharacteristic = null;
            ledCharacteristic = null;
        }
    }

    /**
     * Sends a request to the device to turn the LED on or off.
     *
     * @param on true to turn the LED on, false to turn it off.
     */
    public void turnLed(final boolean on) {
        // Are we connected?
        if (ledCharacteristic == null)
            return;

        // No need to change?
        if (ledOn == on)
            return;

        log(Log.VERBOSE, "Turning LED " + (on ? "ON" : "OFF") + "...");
        writeCharacteristic(ledCharacteristic,
                on ? BlinkyLED.turnOn() : BlinkyLED.turnOff())
                .with(ledCallback).enqueue();
    }
}
