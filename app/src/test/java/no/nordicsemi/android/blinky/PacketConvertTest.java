package no.nordicsemi.android.blinky;

import androidx.annotation.RestrictTo;
import androidx.core.widget.TextViewCompat;

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
        FruityPacket.ConnPacketEncryptCustomStart packet = new FruityPacket.ConnPacketEncryptCustomStart(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_START, 259, 100, 1,
                FruityPacket.FmKeyId.NODE, 1, 57);
        byte expect[] = {0x19, 0x03, 0x01, 0x64, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, (byte) 0xE5};
        assertThat("convert", FruityPacket.createEncryptCustomStartPacket(packet), is(expect));
    }

    @Test
    public void first_handshake_Test() {
        FruityPacket.ConnPacketEncryptCustomStart packet = new FruityPacket.ConnPacketEncryptCustomStart(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_START, 259, 0, 1,
                FruityPacket.FmKeyId.NODE, 0, 0);
        byte expect[] = {25, 3, 1, 0, 0, 1, 1, 0, 0, 0, 0};
        assertThat("convert", FruityPacket.createEncryptCustomStartPacket(packet), is(expect));
    }

    @Test
    public void sNonce_Convert_Test() {
        int sNonce[] = new int[]{1689834492, 434638765};
        FruityPacket.ConnPacketEncryptCustomSNonce customSNonce = new FruityPacket.ConnPacketEncryptCustomSNonce(
                FruityPacket.MessageType.ENCRYPT_CUSTOM_SNONCE, 1, 2,
                sNonce[0], sNonce[1]);
        byte[] expect = new byte[]{0x1B, 0x01, 0x00, 0x02, 0x00, (byte) 0xFC, (byte) 0xD3, (byte) 0xB8, 0x64, (byte) 0xAD, 0x0F, (byte) 0xE8, 0x19};
        assertThat("snonce", FruityPacket.createEncryptCustomSNonce(customSNonce), is(expect));
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
        byte expect[] = new byte[]{0x03, 0x1C, (byte) 0xBD, (byte) 0xBA, 0x73, 0x42, (byte) 0xFD, (byte) 0xB0, (byte) 0x95, 0x13, (byte) 0x81, (byte) 0xAB, (byte) 0x97, (byte) 0x94, (byte) 0x8C, (byte) 0xD9};
        assertThat("encrypt", FruityPacket.generateSecretKey(plainText, new SecretKeySpec(secretKey, "AES")), is(expect));
    }

    @Test
    public void create_ANonce_Encrypt_Plaint_Text_Test() {
        int aNonce[] = new int[]{1325026333, 711465266};
        int nodeId = FruityPacket.nodeId;
        byte expect[] = new byte[]{
                0x77, 0x02, 0x1D, 0x4C, (byte) 0xFA, 0x4E, 0x32, 0x19, 0x68, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        assertThat("plainText", FruityPacket.createPlainTextForSecretKey(FruityPacket.nodeId, aNonce), is(expect));
    }

    @Test
    public void get_SenderId_From_Packet_Header_Test() {
        // sender: 259
        byte packet[] = {0x01, 0x03, 0x01, 0x64, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00};
        assertThat("senderId", FruityPacket.getSenderId(new Data(packet)), is(259));
    }
}
