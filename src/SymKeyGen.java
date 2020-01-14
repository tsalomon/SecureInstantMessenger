import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

/**
 * SymKeyGen
 * Handles the generation of symmetric keys for this assignment
 */
 class SymKeyGen {
	
	static int SUB_KEY_SIZE = 128 / 8;
	private static String ALGO = "AES";
	private static String FULL_ALGO = "AES/CBC/PKCS5Padding";
	static int NUM_BYTES_IV = 16;


    /**
     * generateMasterKey
     * @return A newly generated and encoded master key
     */
    static byte[] generateMasterKey(){
		SecretKey master = generateSecretKey(256, ALGO);
		byte[] mKey = master.getEncoded();
		return mKey;
	}
	
	static byte[][] splitMasterKey(byte[] master){
		
		byte[][] subKeys = new byte[2][SUB_KEY_SIZE];
		subKeys[0] = Arrays.copyOfRange(master, 0, SUB_KEY_SIZE);
		subKeys[1] = Arrays.copyOfRange(master, SUB_KEY_SIZE, master.length);
		assert subKeys[0].length == SUB_KEY_SIZE && subKeys[1].length == SUB_KEY_SIZE;

		return subKeys;
	}
	
	static SecretKey[] convertKeyBytes(byte[][] subKeys){

		return new SecretKey[]{new SecretKeySpec(subKeys[0],ALGO),
							new SecretKeySpec(subKeys[1],ALGO)};
	}


    /**generateSecretKey
     * @param keySize The size of the key to generate
     * @param algo The type of algorithm to use to generate
     * @return A fresh SecretKey
     */
    private static SecretKey generateSecretKey(int keySize, String algo){
		SecretKey key = null;
		try {
			KeyGenerator gen = KeyGenerator.getInstance(algo);
			gen.init(keySize);
			key = gen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return key;
	}
	
	static IvParameterSpec generateInitVector(){
		SecureRandom rngIV = new SecureRandom();
		byte[] iv = new byte[NUM_BYTES_IV];
		rngIV.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	static String encode64(byte[] arr){
		return Base64.encode(arr);
	}
	
	static byte[] decode64(String arr){
		return Base64.decode(arr);
	}

    /**encryptMessage
     * Encrypt a message using a SecretKey and initialization vector
     * @param msg The message to encrypt
     * @param key The SecretKey to use when encrypting the message
     * @param iv  The initialization vector for the cipher (ECB)
     * @return The byte[] representation of the message
     */
    static byte[] encryptMessage(String msg, SecretKey key, byte[] iv){
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), ALGO);
		Cipher cipher;
		byte[] encryptedMessage = null;

		try {
			cipher = Cipher.getInstance(FULL_ALGO);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

			encryptedMessage = cipher.doFinal(msg.getBytes());

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Symmetric Encryption: Exception!");
			e.printStackTrace();
		}
		return encryptedMessage;
	}

    /**decryptMessage
     * @param eMsg The byte[] representation of the encoded message. To be decrypted.
     * @param key The secret key used when encoding the message
     * @param iv The initialization vector used for the cipher (ECB)
     * @return The decrypted message as a String
     */
    static String decryptMessage(byte[] eMsg, SecretKey key, byte[] iv){
		SecretKeySpec sessionKeySpec = new SecretKeySpec(key.getEncoded(), ALGO);
		Cipher cipher;
		String msg = null;
		
		try {
			cipher = Cipher.getInstance(FULL_ALGO);			
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, sessionKeySpec, ivSpec);
			byte[] decryptedMessageBytes = cipher.doFinal(eMsg); 
			msg = new String(decryptedMessageBytes);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Symmetric Decryption: Exception!");
			e.printStackTrace();
		}
		
		return msg;
		
	}

}


