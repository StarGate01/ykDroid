package net.pp3345.ykdroid.yubikey;

import android.nfc.tech.IsoDep;

import net.pp3345.ykdroid.YubiKey;
import net.pp3345.ykdroid.apdu.command.iso.SelectFileApdu;
import net.pp3345.ykdroid.apdu.command.ykoath.PutApdu;
import net.pp3345.ykdroid.apdu.response.ykoath.PutResponseApdu;

import java.io.IOException;

/**
 * NFC YubiKey driver implementation.
 */
public class NfcYubiKey implements YubiKey {
	private final IsoDep tag;

	/**
	 * The scheme of the URI passed in the initial NDEF messages sent by YubiKey NEOs.
	 */
	public static final  String YUBIKEY_NEO_NDEF_SCHEME = "https";
	/**
	 * The host name of the URI passed in the initial NDEF messages sent by YubiKey NEOs.
	 */
	public static final  String YUBIKEY_NEO_NDEF_HOST   = "my.yubico.com";
	/**
	 * ISO 7816 Application ID for the challenge-response feature of YubiKeys.
	 */
	private static final byte[] CHALLENGE_AID_YUBIKEY   = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01};
	private static final byte[] CHALLENGE_AID_FIDESMO   = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x06, 0x17, 0x00, 0x07, 0x53, 0x4E, (byte) 0xAF, 0x01};

	/**
	 * Should only be instantiated by the {@link net.pp3345.ykdroid.ConnectionManager}.
	 *
	 * @param tag YubiKey NEOs provide the functionality of ISO-DEP (14443-4) tags.
	 */
	public NfcYubiKey(final IsoDep tag) {
		this.tag = tag;
	}

	private void ensureConnected() throws IOException {
		if (!this.tag.isConnected()) {
			this.tag.connect();
			this.tag.setTimeout(10000);
		}
	}

	@Override
	public byte[] challengeResponse(final Slot slot, final byte[] challenge) throws YubiKeyException {
		slot.ensureChallengeResponseSlot();

		try {
			this.ensureConnected();

			SelectFileApdu selectFileApdu = new SelectFileApdu(SelectFileApdu.SelectionControl.DF_NAME_DIRECT, SelectFileApdu.RecordOffset.FIRST_RECORD, CHALLENGE_AID_YUBIKEY);
			if (!selectFileApdu.parseResponse(this.tag.transceive(selectFileApdu.build())).isSuccess()) {
				selectFileApdu = new SelectFileApdu(SelectFileApdu.SelectionControl.DF_NAME_DIRECT, SelectFileApdu.RecordOffset.FIRST_RECORD, CHALLENGE_AID_FIDESMO);
				if (!selectFileApdu.parseResponse(this.tag.transceive(selectFileApdu.build())).isSuccess()) {
					throw new FailedOperationException();
				}
			}

			final PutApdu         putApdu         = new PutApdu(slot, challenge);
			final PutResponseApdu putResponseApdu = putApdu.parseResponse(this.tag.transceive(putApdu.build()));

			if (!putResponseApdu.isSuccess()) {
				throw new FailedOperationException();
			}

			return putResponseApdu.getResult();
		} catch (final IOException e) {
			throw new ConnectionLostException(e);
		}
	}
}
