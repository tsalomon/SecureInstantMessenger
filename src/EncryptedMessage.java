import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

class EncryptedMessage extends Message{

    private static final long serialVersionUID = 1L;
	private byte[] iv = new byte[SymKeyGen.NUM_BYTES_IV];
	private byte[] message;
	private byte[] messageAuthCode;

	/**
	 * EncryptedMessage
	 * Allows toggling Confidentiality and Integrity through {@code boolean} parameters.
	 * @param message
     *      The message being sent
	 * @param key
     *      The key being used to encrypt the message
	 * @param macKey
     *      The message authentication code
	 * @param enableConfidential
     *      Inherited from paramArray[0]: Toggles encryption
	 * @param enableIntegrity
     *      Inherited from paramArray[1]: Toggles MAC
	 */
	EncryptedMessage(String message, SecretKey key, SecretKey macKey, boolean enableConfidential, boolean enableIntegrity){
		super(message);
		this.iv = SymKeyGen.generateInitVector().getIV();

		if (enableConfidential) { this.message = SymKeyGen.encryptMessage(message, key, this.iv); }
		else { this.message = message.getBytes(); }

		if (enableIntegrity) { this.messageAuthCode = generateMAC(this.message, macKey); }
		else { this.messageAuthCode = null; }
	}

    byte[] getMessage() { return this.message; }

    String decrypt(SecretKey key){ return SymKeyGen.decryptMessage(this.message, key, this.iv); }

    /** generateMAC
     * @param data The data used when generating the MAC
     * @param key The key used to create the MAC
     * @return The requested MAC
     */
    private byte[] generateMAC(byte[] data, SecretKey key){

		byte[] macSig = null;
		try {
			  Mac theMac = Mac.getInstance("HmacSHA256");
			  theMac.init(key);

			  macSig = theMac.doFinal(data);
		}
		catch (NoSuchAlgorithmException | InvalidKeyException ex) { ex.printStackTrace(); }

		return macSig;
	}

    /** verifyMac
     * @param macKey The key used to generate the message authentication code (MAC)
     * @return true if the generated MAC matches the message's MAC, false otherwise
     */
    boolean verifyMAC(SecretKey macKey) {

        if (this.message != null) {
            byte[] newMac = generateMAC(this.message, macKey);
            String encodedNewMac = SymKeyGen.encode64(newMac);
            String encodedMac = SymKeyGen.encode64(this.messageAuthCode);

            if (encodedNewMac.equals(encodedMac)) {
                return true;
            }
        }
        return false;
    }
}