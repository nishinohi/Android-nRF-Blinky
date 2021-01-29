package no.nordicsemi.android.blinky;

import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import no.nordicsemi.android.ble.data.Data;
import no.nordicsemi.android.blinky.profile.packet.FruityPacket;

import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.*;

public class PacketConvertTest {
    @Test
    public void packet_Convert_Test() {
        FruityPacket.ConnPacketEncryptCustomStart packet = new FruityPacket.ConnPacketEncryptCustomStart();
        packet.header = new FruityPacket.ConnPacketHeader();
        packet.header.messageType = FruityPacket.MessageType.ENCRYPT_CUSTOM_START;
        packet.header.sender = 259;
        packet.header.receiver = 100;
        packet.version = 1;
        packet.fmKeyId = FruityPacket.FmKeyId.NODE;
        packet.tunnelType = 1;
        packet.reserved = 57;
        byte expect[] = {0x19, 0x03, 0x01, 0x64, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, (byte) 0xE5};
        assertThat("convert", FruityPacket.createEncryptCustomStartPacket(packet), is(expect));
    }

    @Test
    public void first_handshake_Test() {
        FruityPacket.ConnPacketEncryptCustomStart packet = new FruityPacket.ConnPacketEncryptCustomStart();
        packet.header = new FruityPacket.ConnPacketHeader();
        packet.header.messageType = FruityPacket.MessageType.ENCRYPT_CUSTOM_START;
        packet.header.sender = 259;
        packet.header.receiver = 0;
        packet.version = 1;
        packet.fmKeyId = FruityPacket.FmKeyId.NODE;
        packet.tunnelType = 0;
        packet.reserved = 0;

        byte expect[] = {25, 3, 1, 0, 0, 1, 1, 0, 0, 0, 0};
        assertThat("convert", FruityPacket.createEncryptCustomStartPacket(packet), is(expect));
    }

    @Test
    public void aNonce_First_Second_Test() {
        Data data = new Data(new byte[]{0x1A, 0x3, 0x1, 0x3, 0x1, 0x41, 0x32, (byte) 0xDE, (byte) 0x95, (byte) 0xE3, (byte) 0xE2, 0x7A, 0x6});
        int expext[] = new int[]{-1780600255, 108716771};
        assertThat("anonce", FruityPacket.readEncryptCustomANonce(data), is(expext));
    }

    @Test
    public void aNonce_Encrypt_Test() throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte plainText[] = new byte[]{0x01, 0x00, 0x1D, 0x4C, (byte) 0xFA, 0x4E, 0x32, 0x19, 0x68, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0};
        byte secretKey[] = new byte[]{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        assertThat("encrypt", FruityPacket.encryptAES128(plainText, new SecretKeySpec(secretKey, "AES")), is(plainText));
    }
}
