package no.nordicsemi.android.blinky.profile.module;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import no.nordicsemi.android.blinky.profile.packet.FruityPacket;

public abstract class Module {
    public Module(String moduleName, byte moduleId) {
        this.moduleName = moduleName;
        this.moduleId = moduleId;
    }

    protected String moduleName;
    protected byte moduleId;

    //TODO: reliable is currently not supported and by default false. The input is ignored
    public byte[] createSendModuleActionMessagePacket(FruityPacket.MessageType messageType,
                                                             short receiver, byte requestHandle, byte actionType,
                                                             byte[] additionalData, int additionalDataSize, boolean reliable) {
        ByteBuffer packetBuf = ByteBuffer.allocate(FruityPacket.ConnPacketModule.SIZEOF_CONN_PACKET_MODULE + additionalDataSize).order(ByteOrder.LITTLE_ENDIAN);
        packetBuf.put(messageType.getTypeValue());
        packetBuf.put(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) FruityPacket.nodeId).array());
        packetBuf.put(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(receiver).array());
        packetBuf.put(this.moduleId);
        packetBuf.put(requestHandle);
        packetBuf.put(actionType);
        if (additionalData != null) packetBuf.put(additionalData);
        return packetBuf.array();
    }
}
