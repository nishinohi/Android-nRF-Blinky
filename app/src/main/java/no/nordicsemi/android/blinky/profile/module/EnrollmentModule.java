package no.nordicsemi.android.blinky.profile.module;

import androidx.annotation.NonNull;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import no.nordicsemi.android.blinky.profile.module.Module;

public class EnrollmentModule extends Module {
    public EnrollmentModule() {
        super("enroll", (byte) 5);
    }

    public static enum EnrollmentModuleTriggerActionMessages {
        SET_ENROLLMENT_BY_SERIAL((byte) 0),
        REMOVE_ENROLLMENT((byte) 1),
        //SET_ENROLLMENT_BY_SERIAL = 2, //Deprecated since version 0.7.22
        SET_NETWORK((byte) 3),
        REQUEST_PROPOSALS((byte) 4),
        ;

        EnrollmentModuleTriggerActionMessages(byte actionType) {
            this.actionType = actionType;
        }

        private byte actionType;

        public byte getActionType() {
            return actionType;
        }
    }

    public enum EnrollmentModuleActionResponseMessages {
        ENROLLMENT_RESPONSE((byte) 0),
        REMOVE_ENROLLMENT_RESPONSE((byte) 1),
        ENROLLMENT_PROPOSAL((byte) 2),
        SET_NETWORK_RESPONSE((byte) 3),
        REQUEST_PROPOSALS_RESPONSE((byte) 4),
        ;

        EnrollmentModuleActionResponseMessages(byte responseType) {
            this.responseType = responseType;
        }

        private byte responseType;

        public byte getResponseType() {
            return responseType;
        }
    }


    public static class EnrollmentModuleSetEnrollmentBySerialMessage {
        public EnrollmentModuleSetEnrollmentBySerialMessage(
                int serialNumberIndex, short newNodeId, short newNetworkId,
                @NonNull byte[] newNetworkKey, byte[] newUserBaseKey, byte[] newOrganizationKey,
                byte[] nodeKey, byte timeoutSec, boolean enrollOnlyIfUnenrolled) {
            this.serialNumberIndex = serialNumberIndex;
            this.newNodeId = newNodeId;
            this.newNetworkId = newNetworkId;
            // newNetworkKey is never null
            System.arraycopy(newNetworkKey, 0, this.newNetworkKey, 0, 16);
            System.arraycopy(newUserBaseKey == null ?
                    new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} :
                    newUserBaseKey, 0, this.newUserBaseKey, 0, 16);
            System.arraycopy(newOrganizationKey == null ?
                    new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} :
                    newOrganizationKey, 0, this.newOrganizationKey, 0, 16);
            System.arraycopy(nodeKey == null ?
                    new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} :
                    nodeKey, 0, this.nodeKey, 0, 16);
            this.timeoutSec = timeoutSec;
            this.enrollOnlyIfUnenrolled = enrollOnlyIfUnenrolled;
        }

        public static int SIZEOF_ENROLLMENT_MODULE_SET_ENROLLMENT_BY_SERIAL_MESSAGE = 73;

        private int serialNumberIndex;
        private short newNodeId;
        private short newNetworkId;
        private byte[] newNetworkKey = new byte[16];
        private byte[] newUserBaseKey = new byte[16];
        private byte[] newOrganizationKey = new byte[16];
        private byte[] nodeKey = new byte[16]; // Key used to connect to the unenrolled node
        private byte timeoutSec; //how long to try to connect to the unenrolled node, 0 means default time
        private boolean enrollOnlyIfUnenrolled; //Set to 1 in order to return an error if already enrolled
    }

    public byte[] createEnrollmentModuleSetEnrollmentBySerialMessagePacket(EnrollmentModuleSetEnrollmentBySerialMessage enrollMessage) {
        ByteBuffer packetBuf = ByteBuffer.allocate(
                EnrollmentModuleSetEnrollmentBySerialMessage.SIZEOF_ENROLLMENT_MODULE_SET_ENROLLMENT_BY_SERIAL_MESSAGE).order(ByteOrder.LITTLE_ENDIAN);
        packetBuf.putInt(enrollMessage.serialNumberIndex);
        packetBuf.putShort(enrollMessage.newNodeId);
        packetBuf.putShort(enrollMessage.newNetworkId);
        packetBuf.put(enrollMessage.newNetworkKey);
        packetBuf.put(enrollMessage.newUserBaseKey);
        packetBuf.put(enrollMessage.newOrganizationKey);
        packetBuf.put(enrollMessage.nodeKey);
        byte lastTwoValue = enrollMessage.enrollOnlyIfUnenrolled ? (byte) 1 : (byte) 0;
        lastTwoValue = (byte) (lastTwoValue << 7);
        lastTwoValue = (byte) (lastTwoValue | enrollMessage.timeoutSec);
        packetBuf.put(lastTwoValue);
        return packetBuf.array();
    }

}
