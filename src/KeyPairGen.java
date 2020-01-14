import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import sun.security.x509.*;

import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class KeyPairGen {
	
	public static char[] KEYSTORE_PASS = "abcde".toCharArray();
	public static String KEYSTORE_PATH = System.getProperty("user.dir") + File.separator + "keyStores"+ File.separator;
	public static String CLIENT_KEYSTORE = "clientKeys.store";
	public static String SERVER_KEYSTORE = "serverKeys.store";
	public static String SERVER_ALIAS = "Server";
	public static String CLIENT_ALIAS = "Client";

    public static KeyPair generateKeyPair(){
		KeyPair kp = null;
		try {
			KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");
			factory.generateKeyPair();
			kp = factory.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("alg not found");
		}
		return kp;	
	}

	/**	createKeyStores
     * server keystore: private and public keys
     * client keystore: private and public keys
     * public keystore: server and client public keys
	 * 	1. Create the KeyStore folder
     * 	2. Initialize the KeyStores
     * 	3. Generate certificates
     * 	4. Sign the certificates
     * 	5. Build certificate chain for verification
     * 	6. Fill KeyStores with necessary data
     * 	7. Write KeyStores to disk
     * 	8. Verify Client cert is signed by server's public key
     * 	9. Verify Server cert is signed by server's public key
	 * @param ckp Client KeyPair
	 * @param skp Server KeyPair
     */
	private static void createKeyStores(KeyPair ckp, KeyPair skp){
		try{
			
			//create the keystore folder
			File keyStoreDir = new File(KEYSTORE_PATH);
			if(keyStoreDir.exists()){
				for(File file: keyStoreDir.listFiles()){
					file.delete();
				}
			}
			keyStoreDir.mkdirs();

			//initialize the keystores
			File cfile = new File(KEYSTORE_PATH + CLIENT_KEYSTORE);
			File sfile = new File(KEYSTORE_PATH + SERVER_KEYSTORE);
			KeyStore client = KeyStore.getInstance(KeyStore.getDefaultType());
			KeyStore server = KeyStore.getInstance(KeyStore.getDefaultType());
	
			client.load(null, null);
			server.load(null, null);
			
			//generate certificates
			X509Certificate clientCert = generateCertificate("CN=Jory, OU=JavaSoft, O=Sun Microsystems, C=CA", ckp, 100, "SHA1withRSA");
			X509Certificate serverCert = generateCertificate("CN=Tim, OU=JavaSoft, O=Sun Microsystems, C=CA", skp, 100, "SHA1withRSA");

			//sign the certificates (server is CA; is root cert)
			serverCert = createSignedCertificate(serverCert,serverCert,skp.getPrivate());
			clientCert = createSignedCertificate(clientCert,serverCert,skp.getPrivate());
			
			//build the certificate chain for verification
			Certificate[] clientCertChain = new Certificate[2];
			Certificate[] serverCertChain = new Certificate[2];

			clientCertChain[0] = clientCert;
			clientCertChain[1] = serverCert;
			
			serverCertChain[0] = serverCert;
			serverCertChain[1] = serverCert;
			
			//fill keystores with necessary data
			char[] privateKeyPass = "keypass".toCharArray();
			client.setKeyEntry("ClientPrivate", ckp.getPrivate(),privateKeyPass,clientCertChain);
			client.setCertificateEntry("ClientCert", clientCert);
			client.setCertificateEntry("ServerCert", serverCert);

			server.setKeyEntry("ServerPrivate", skp.getPrivate(),privateKeyPass,serverCertChain);
			server.setCertificateEntry("ClientCert", clientCert);
			server.setCertificateEntry("ServerCert", serverCert);

			//write keystores to disk
			client.store(new FileOutputStream(cfile), KEYSTORE_PASS);
			server.store(new FileOutputStream(sfile), KEYSTORE_PASS);
			
			//verify client cert is signed by server's public key
			Certificate clientCheck = server.getCertificate("ClientCert");
			try{
				clientCheck.verify(server.getCertificate("ServerCert").getPublicKey());				
				System.out.println("Client cert valid. Signed by server's public key.");

			}catch(InvalidKeyException ivky){
				System.out.println("Client cert not valid. Not signed by server's public key.");
			}
			
			//verify server cert is signed by server's public key
			Certificate serverCheck = client.getCertificate("ServerCert");
			try{
				serverCheck.verify(client.getCertificate("ServerCert").getPublicKey());				
				System.out.println("Server cert valid. Signed by server's (the CA) public key.");

			}catch(InvalidKeyException ivky){
				System.out.println("Server cert not valid. Not signed by server's (the CA) public key.");
			}
			
		}catch(Exception e){
			System.out.println("AKeyGen: could not create key stores");
			e.printStackTrace();
		}
	}

    /** retrieveKeyStore
     * @param path The path to the keyStore
     * @return A keyStore object representation of the keyStore files
     */
    public static KeyStore retrieveKeyStore(String path){
		File ks = new File(path);
		KeyStore keyStore = null;
		
		try{
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(new FileInputStream(ks), KEYSTORE_PASS);
		}catch(KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e){
			System.out.println("Could not retrieve keyStore: " + path);
		}
		
		return keyStore;
	}
	
	public static KeyStore loadClientKeyStore(){
		return KeyPairGen.retrieveKeyStore(KEYSTORE_PATH + CLIENT_KEYSTORE);
	}
	public static KeyStore loadServerKeyStore(){
		return KeyPairGen.retrieveKeyStore(KEYSTORE_PATH + SERVER_KEYSTORE);
	}

    /** b64Key
     * @param key The key to encode
     * @return The key encoded in base64
     */
    public static String b64Key(Key key){
		byte[] keyBytes = key.getEncoded();
		return Base64.encode(keyBytes);
	}

	/** 
	 * Create a self-signed X.509 Certificate
	 * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
	 * @param pair the KeyPair
	 * @param days how many days from now the Certificate is valid for
	 * @param algorithm the signing algorithm, eg "SHA1withRSA"
	 */ 
	public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
	  throws GeneralSecurityException, IOException
	{
	  PrivateKey privkey = pair.getPrivate();
	  X509CertInfo info = new X509CertInfo();
	  Date from = new Date();
	  Date to = new Date(from.getTime() + days * 86400000l);
	  CertificateValidity interval = new CertificateValidity(from, to);
	  BigInteger sn = new BigInteger(64, new SecureRandom());
	  X500Name owner = new X500Name(dn);
	 
	  info.set(X509CertInfo.VALIDITY, interval);
	  info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
	  info.set(X509CertInfo.SUBJECT, owner);
	  info.set(X509CertInfo.ISSUER, owner);
	  info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
	  info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
	  AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
	  info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
	 
	  // Sign the cert to identify the algorithm that's used.
	  X509CertImpl cert = new X509CertImpl(info);
	  cert.sign(privkey, algorithm);
	 
	  // Update the algorith, and resign.
	  algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
	  info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
	  cert = new X509CertImpl(info);
	  cert.sign(privkey, algorithm);
	  return cert;
	}

    /** createSignedCertificate
     * @param certificate The type of certificate being used
     * @param issuerCertificate The certificate issuer
     * @param issuerPrivateKey The issuer's private key
     * @return  The signed certificate
     */
    private static X509Certificate createSignedCertificate(X509Certificate certificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey){
        try{
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();
              
            byte[] inCertBytes = certificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, issuer);
              
            //No need to add the BasicContraint for leaf cert
            if(!certificate.getSubjectDN().getName().equals("CN=TOP")){
                CertificateExtensions exts=new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }
              
            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);
              
            return outCert;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }

    public static boolean verifySignature(Certificate certToVerify, Certificate caCert){

			try {
				certToVerify.verify(caCert.getPublicKey());
			} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                                        | NoSuchProviderException | SignatureException e) {
				e.printStackTrace();
				return false;
			}				
		
		return true;
	}

    /** encrypt
     * @param message The message/data to encrypt
     * @param key The key (symmetric) used when encrypting
     * @return the encrypted byte[] array
     */
    public static byte[] encrypt(String message, Key key){
    	
		//System.out.println("KPGen: encrypting bytes: " + message.getBytes().length);

    	byte[] encBytes = null;
    	
    	try {
        	Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
			pkCipher.init(Cipher.ENCRYPT_MODE, key);
			encBytes = pkCipher.doFinal(message.getBytes());
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return encBytes;
    
    }

    /** decrypt
     * @param encBytes The bytes to be decrypted
     * @param key The key used when decrypting encBytes
     * @return The decrypted plaintext
     */
    public static String decrypt(byte[] encBytes, Key key){
    	
		//System.out.println("KPGen: decrypting bytes: " + encBytes.length);

    	String decrypted = null;
    	
    	try {
        	Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
			pkCipher.init(Cipher.DECRYPT_MODE, key);
			decrypted = new String(pkCipher.doFinal(encBytes));
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return decrypted;
    
    }


    /** main
     * Generates KeyPairs for the Server and Client, then stores them in a file (keyStore)
     * Tests the keyStores by encrypting a text with the Server public key, then decrypts with the
     * Server private key.
     * @param args N/A
     */
    public static void main(String[] args){
		
		try{
		KeyPair server = KeyPairGen.generateKeyPair();
		KeyPair client = KeyPairGen.generateKeyPair();
		
		if(server == null || client == null){
			System.out.println("null");
		}

		System.out.println("Server Private Key:\n" + b64Key(server.getPrivate()));
		System.out.println("Server Public Key:\n" + b64Key(server.getPublic()));
		System.out.println("Client Private Key:\n" + b64Key(client.getPrivate()));
		System.out.println("Client Public Key:\n" + b64Key(client.getPublic()));
		
		KeyPairGen.createKeyStores(client, server);
		System.out.println("Client and Server KeyStores created.");
		
		String testMsg = "secret";
		byte[] encTestMsg = KeyPairGen.encrypt(testMsg, server.getPublic());
		System.out.println("Encrypted message: "+ new String(encTestMsg) );
		String decTestMsg = KeyPairGen.decrypt(encTestMsg, server.getPrivate());
		
		System.out.println("Decrypted message: "+ decTestMsg);
		}catch(Exception e){
			e.printStackTrace();
		}
		
	
	}
	
	
}
	

