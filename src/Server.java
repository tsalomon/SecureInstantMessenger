import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.crypto.SecretKey;


class Server {

	private ServerSocket server;
	private Socket clientSocket;

    private boolean[] serverParams;
	
	private boolean enableA;
    boolean enableI;
    boolean enableC;

	private DataInputStream is;
	private DataOutputStream os;
	private ObjectInputStream objIn;
    ObjectOutputStream objOut;

    SecretKey[] sessionKeys = {null, null};
    private KeyStore keyStore;
    
    ServerMsgGUI gui;

    /** startServer
     * Grabs Server parameters, creates a socket @ port 11112 and listens for another connection
     */
    void startServer() {

		serverParams = gui.params;
		enableC = serverParams[0];
		enableI = serverParams[1];
		enableA = serverParams[2];
		
		gui.printStatus("Starting Server...");

		try {

            int PORT = 11112;
            server = new ServerSocket(PORT);
			keyStore = KeyPairGen.loadServerKeyStore();
			while (true) {
				connect();
			}
			
		} catch (IOException e) {
			gui.printStatus("ERROR! Could not start server.");
		}
	}

    /** connect
     *  Once a connection is established, compare parameters. Rejects connection if they do not match.
     */
    private void connect() {

		waitForConnection();
		if (parametersMatch()) { 
			beginConnection(); 
		}
		else { closeSocketAndStreams(); }

	}

    /** waitForConnection
     *  The server listens for a connection @ server.accept(),
     *  which the streams are initialize and a connection is made
     */
    private void waitForConnection() {
		try {
			gui.printStatus("Listening...");
			clientSocket = server.accept();
			gui.printStatus("Received connection request from Client.");
			initializeStreams();
		} catch (IOException e) {
			gui.printStatus("ERROR! Could not accept connection from Client.");
			//e.printStackTrace();
		}
	}

    /** getClientParameters
     * Used in parametersMatch() to grab the client parameters
     * @return The client parameters as a string
     */
    private String getClientParameters() {
		
		String clientParams = "";
		try {
			Message paramsMsg = (Message) objIn.readObject();
			clientParams = paramsMsg.get();
			//gui.printStatus("Server: Client Parameters Received: "+ clientParams);
		} catch (IOException | ClassNotFoundException e) {
			gui.printStatus("ERROR! Did not recieve client parameters.");
			//e.printStackTrace();
		}
		return clientParams;
		
	}


    /** initializeStreams
     * Handles initializing the Streams used to communicate with the Client
     * (See closeStreamsAndSockets)
     * @throws IOException If clientSocket is null, or Stream object could not be created
     */
    private void initializeStreams() throws IOException {

		objIn = new ObjectInputStream(clientSocket.getInputStream());
		objOut = new ObjectOutputStream(clientSocket.getOutputStream());
		is = new DataInputStream(clientSocket.getInputStream());
		os = new DataOutputStream(clientSocket.getOutputStream());
	
	}

    /** parametersMatch
     * @return true if Server parameters match Client's, false otherwise
     */
    private boolean parametersMatch() {
		
		String serverP = Arrays.toString(serverParams);
		String clientP = getClientParameters();
		boolean sameConfig = serverP.equals(clientP);

		if (sameConfig) {
			gui.printStatus("Parameters match Client's.");
			gui.printStatus("Connection to Client open.");

		} else {
			gui.printStatus("ERROR! Client and Server parameters do not match.");
        }

        try {
            objOut.writeBoolean(sameConfig);
            objOut.flush();
        } catch (IOException e) {
			gui.printStatus("ERROR! Could not send parameters acknowledgement.");
            //e.printStackTrace();
        }

        return sameConfig;
	}

    /** authClientCert
     * Reads in Client's Cert, then generates one for Server, then writes that out to Client.
     * @return true if Client and Server are mutually authenticated, false otherwise
     */
    private boolean authClientCert() {
		
		//gui.printStatus("Server: Waiting for client to send certificate.");
		Certificate clientCert = null;
		try {
			clientCert = (Certificate) objIn.readObject();
		} catch (ClassNotFoundException | IOException e) {
			gui.printStatus("ERROR! Could not receive Client's certificate.");
		}

		Certificate caCert = null;
		try {
            caCert = keyStore.getCertificate("ServerCert");
            gui.printStatus("ERROR! Could not retrieve Server's certificate from the KeyStore.");
            if (!KeyPairGen.verifySignature(clientCert, caCert)) {
                gui.printStatus("ERROR! The Client's certificate is invalid.");
                return false;
            }
        } catch (KeyStoreException e1) {
            gui.printStatus("ERROR! Could not retrieve Server's certificate from the KeyStore.");
        }

		try {
			objOut.writeBoolean(true);
			objOut.flush();
			objOut.writeObject(caCert);

			boolean success = objIn.readBoolean();
			
			if(success){
				gui.printStatus("SUCCESS! Mutual authentication complete.");
			}else{
				gui.printStatus("ERROR! Server's certificate is invalid.");
			}
			
		} catch (IOException e) {
			gui.printStatus("ERROR! Mutual authentication interrupted.");
			return false;
		}

		return true;
	}

    /** beginConnection()
     * 1. If Authentication is enabled, the Server will need to authenticate itself for the Client
     * 2. If Integrity or Confidentiality are enabled, the Server will need to establish session keys
     * 3. Messaging is enabled, monitor for received messages
     */
    private void beginConnection() {
		
		boolean authSuccess;
		if(enableA){
			authSuccess = authClientCert();
			if(!authSuccess){
				gui.printStatus("ERROR! Mutual authentication failed. Connection closed.");
				closeSocketAndStreams();
				return;
			}
		}

		//session key establishment if enabled
		if (enableC || enableI) {

			try {
				gui.printStatus("Connection to Client open.");
				
				sessionKeys = null;
				gui.printStatus("Waiting for Client to begin session key establishment.");
				PrivateKey serverPriKey = (PrivateKey) keyStore.getKey("ServerPrivate", "keypass".toCharArray());

				int encryptedMKeySizeBytes = SymKeyGen.SUB_KEY_SIZE * 8;
				byte[] encryptedMKey = new byte[encryptedMKeySizeBytes];
				objIn.read(encryptedMKey, 0, encryptedMKeySizeBytes);

				String decryptedKey = KeyPairGen.decrypt(encryptedMKey, serverPriKey);
				sessionKeys = SymKeyGen.convertKeyBytes(SymKeyGen.splitMasterKey(SymKeyGen.decode64(decryptedKey)));
				gui.printStatus("SUCCESS! Session key established.");
				gui.printStatus("You can now send messages.");
		
			} catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
				gui.printStatus("ERROR! Could not obtain/decrypt session keys.");
				//e.printStackTrace();
			}
		}

		gui.enableMessaging(true);
		
		try{
			
			ExecutorService executor = Executors.newSingleThreadExecutor();
			Callable<Boolean> t = this.new ReceiveMessagesTask();
	        Future<Boolean> future = executor.submit(t);

	        boolean finish = false;
	        try {
	        	finish = future.get();
			} catch (InterruptedException | ExecutionException e) { e.printStackTrace(); }
	        
			if(!finish){
				throw new Exception("message reception exception");
			}
			
		}catch(Exception ex) // catch the wrapped exception sent from within the thread
	    {
			closeSocketAndStreams();
			//gui.setVisible(false);
			gui.enableMessaging(false);
			gui.clearChat();
			gui.printStatus("Server: ERROR! Connection closed.");
	    }
	}

    /**
     * Performs this task whenever a message is received from the client.
     * 1. Reads the object
     * 2. Verifies integrity by verifying the MAC
     *      a. Decrypts the message if necessary
     * 2b. If integrity checks are disabled, message still needs to be decrypted
     */
    class ReceiveMessagesTask implements Callable<Boolean> {
	    public Boolean call() throws Exception {
	    	try {
				while (true) {

					Object msg;
					
						if ((msg = objIn.readObject()) != null) {
							EncryptedMessage recEMsg = ((EncryptedMessage) msg);

							String output;

							if (enableI) {

								// verify message
								if (recEMsg.verifyMAC(sessionKeys[1])) {
									gui.printStatus("Message verified.");

									// also decrypt message if necessary
									if (enableC) {
										output = recEMsg
												.decrypt(sessionKeys[0]);
										gui.printStatus("Message decrypted.");
									} else {
										output = new String(
												recEMsg.getMessage());
									}

									printMessage("Client: " + output);
								} else {
									gui.printStatus("ERROR! Verification failed.");
								}

								// no integrity checks
							} else {

								// also decrypt message if necessary
								if (enableC) {
									output = recEMsg.decrypt(sessionKeys[0]);
									gui.printStatus("Message decrypted.");
								} else {
									output = new String(recEMsg.getMessage());
								}

								printMessage("Client: " + output);
							}
						}
				}
			} catch (ClassNotFoundException | IOException e) {
				return Boolean.FALSE;
			}
	    }
	}

    void printMessage(String message) {
		String header = "[" + String.format("%tF %<tT", new Date())+ "] ";
		
		gui.printMessageAsync(header + message);
	}

    /** closeSocketAndStreams
     *  Closes all the I/O streams as well as sockets.
     */
    private void closeSocketAndStreams() {
		try {
			os.close();
			is.close();
			objIn.close();
			objOut.close();
			clientSocket.close();
		} catch (IOException e) { e.printStackTrace(); }
	}

    /** authenticate
     * @param user user is checked against the initialized DB
     * @param password password and user are checked against the DB as a (user:password) pair
     * @return true if user exists and password matches, false otherwise
     */
    boolean authenticate(String user, String password){
	    UserDB db = new UserDB();
        if (db.authenticate(user, password)) {
            return true;
        }
        gui.printStatus("Username or password is incorrect. Try again.");
        return false;
    }
}