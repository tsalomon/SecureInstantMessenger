import static java.lang.System.exit;

import java.io.IOException;
import java.io.ObjectOutputStream;

import javax.crypto.SecretKey;
import javax.swing.JScrollBar;
import javax.swing.JTextArea;

public class ServerMsgGUI extends javax.swing.JFrame {

	private static Server server;
	public boolean[] params;

	private javax.swing.JButton authBtn;
	private javax.swing.JCheckBox checkAuth;
	private javax.swing.JCheckBox checkConfidential;
	private javax.swing.JCheckBox checkIntegrity;
	private javax.swing.JLabel jLabel1;
	private javax.swing.JLabel jLabel2;
	private javax.swing.JLabel jLabel3;
	private javax.swing.JPanel jPanel1;
	private javax.swing.JPanel jPanel2;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JScrollPane jScrollPane2;
	private javax.swing.JSeparator jSeparator1;
	private javax.swing.JTextField messageInput;
	private static javax.swing.JTextArea messages;
	private javax.swing.JButton paramConfirmBtn;
	private javax.swing.JPasswordField passwordInput;
	private javax.swing.JButton sendBtn;
	private javax.swing.JTextArea status;
	private javax.swing.JTextField usernameInput;

	public ServerMsgGUI(String title) {
		initComponents();
		this.setTitle(title);
		server = new Server();
		server.gui = this;

		enableMessaging(false);
		enableParams(true);
		enableLogin(false);

		printStatus("Select properties (CIA)...");
	}

	public void runServer(){
		new Thread(){
			public void run(){
				server.startServer();
			}
		}.start();
	}


    /** initComponents
     * Initializes components, then builds the UI. The UI was programmed by a UI designing application
     * by the name of Nimbus(?)
     */
    private void initComponents() {

		sendBtn = new javax.swing.JButton();
		messageInput = new javax.swing.JTextField();
		jScrollPane1 = new javax.swing.JScrollPane();
		messages = new javax.swing.JTextArea();
		jSeparator1 = new javax.swing.JSeparator();
		jScrollPane2 = new javax.swing.JScrollPane();
		status = new javax.swing.JTextArea();
		jLabel3 = new javax.swing.JLabel();
		jPanel1 = new javax.swing.JPanel();
		checkConfidential = new javax.swing.JCheckBox();
		checkAuth = new javax.swing.JCheckBox();
		checkIntegrity = new javax.swing.JCheckBox();
		paramConfirmBtn = new javax.swing.JButton();
		jPanel2 = new javax.swing.JPanel();
		passwordInput = new javax.swing.JPasswordField();
		jLabel2 = new javax.swing.JLabel();
		usernameInput = new javax.swing.JTextField();
		jLabel1 = new javax.swing.JLabel();
		authBtn = new javax.swing.JButton();

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
		setTitle("AsyncMessageIO");
		setResizable(false);

		sendBtn.setText("Send");
		sendBtn.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				sendBtnActionPerformed();
			}
		});

		messages.setEditable(false);
		messages.setColumns(20);
		messages.setRows(5);
		jScrollPane1.setViewportView(messages);

		status.setEditable(false);
		status.setColumns(20);
		status.setRows(5);
		jScrollPane2.setViewportView(status);

		jLabel3.setText("Status:");

		checkConfidential.setText("Confidentiality");
		checkConfidential.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				//checkConfidentialActionPerformed(evt);
			}
		});

		checkAuth.setText("Authentication");

		checkIntegrity.setText("Integrity");

		paramConfirmBtn.setText("Confirm");
		paramConfirmBtn.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				paramConfirmBtnActionPerformed();
			}
		});

		javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
		jPanel1.setLayout(jPanel1Layout);
		jPanel1Layout.setHorizontalGroup(
				jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel1Layout.createSequentialGroup()
						.addContainerGap()
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel1Layout.createSequentialGroup()
										.addComponent(paramConfirmBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(0, 4, Short.MAX_VALUE))
										.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
												.addGap(0, 0, Short.MAX_VALUE)
												.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
														.addComponent(checkIntegrity, javax.swing.GroupLayout.PREFERRED_SIZE, 88, javax.swing.GroupLayout.PREFERRED_SIZE)
														.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
																.addComponent(checkAuth, javax.swing.GroupLayout.Alignment.TRAILING)
																.addComponent(checkConfidential, javax.swing.GroupLayout.Alignment.TRAILING)))))
																.addContainerGap())
				);
		jPanel1Layout.setVerticalGroup(
				jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel1Layout.createSequentialGroup()
						.addContainerGap()
						.addComponent(checkAuth)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addComponent(checkConfidential)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addComponent(checkIntegrity)
						.addGap(18, 18, 18)
						.addComponent(paramConfirmBtn)
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
				);

		jLabel2.setText("Password:");

		jLabel1.setText("Username:");

		authBtn.setText("Authenticate");
		authBtn.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				authBtnActionPerformed();
			}
		});

		javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
		jPanel2.setLayout(jPanel2Layout);
		jPanel2Layout.setHorizontalGroup(
				jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel2Layout.createSequentialGroup()
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
										.addComponent(jLabel1)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(usernameInput, javax.swing.GroupLayout.PREFERRED_SIZE, 159, javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
												.addComponent(jLabel2)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
												.addComponent(passwordInput, javax.swing.GroupLayout.PREFERRED_SIZE, 159, javax.swing.GroupLayout.PREFERRED_SIZE))
												.addComponent(authBtn, javax.swing.GroupLayout.Alignment.TRAILING))
												.addContainerGap())
				);
		jPanel2Layout.setVerticalGroup(
				jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
						.addGap(13, 13, 13)
						.addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(usernameInput, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel1))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(passwordInput, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jLabel2))
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(authBtn)
										.addContainerGap())
				);

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(
				layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
						.addContainerGap()
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jSeparator1)
								.addGroup(layout.createSequentialGroup()
										.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addGroup(layout.createSequentialGroup()
														.addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 232, javax.swing.GroupLayout.PREFERRED_SIZE)
														.addGap(18, 18, 18)
														.addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
														.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
														.addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
														.addComponent(jLabel3))
														.addGap(0, 0, Short.MAX_VALUE))
														.addGroup(layout.createSequentialGroup()
																.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
																		.addComponent(jScrollPane1)
																		.addGroup(layout.createSequentialGroup()
																				.addComponent(messageInput)
																				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
																				.addComponent(sendBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)))
																				.addContainerGap())))
				);
		layout.setVerticalGroup(
				layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
						.addContainerGap()
						.addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 248, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(messageInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(sendBtn))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 2, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jLabel3)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addComponent(jPanel1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addGroup(layout.createSequentialGroup()
												.addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)
												.addGap(0, 0, Short.MAX_VALUE))))
				);

		pack();
	}

    /** paramConfirmBtnActionPerformed
     * Disables the parameter checkboxes/btn once clicked,
     * then enables login if Authentication is enabled, else the server begins to establish a connection to the client
     */
    private void paramConfirmBtnActionPerformed() {
		params = checkParams();       
		printStatus("Properties selected.");
		enableParams(false);

		if(params[2]){
			printStatus("Waiting for authentication.");
			enableLogin(true);
		}else{
			runServer();
		}
	}

    /** authBtnActionPerformed
     * Grabs the user/pass from the input fields and attempts to authenticate them against
     * the UserDB
     */
    private void authBtnActionPerformed() {
		String user = usernameInput.getText();
		String pass = passwordInput.getText();
		if(server.authenticate(user, pass)){
			enableLogin(false);
			runServer();
		}else{
			printStatus("ERROR! Auth failure.");
		}
	}


    /** sendBtnActionPerformed
     * Sends the message to the client once the send button is pressed
     */
    private void sendBtnActionPerformed() {

		String msg = messageInput.getText();
		if(!msg.equals("")){
			server.printMessage("Server(You): " + msg);
			sendMessageAsync(msg, this.server.sessionKeys, this.server.enableC, this.server.enableI, this.server.objOut);
		}

		//auto scroll
		JScrollBar vertical = jScrollPane1.getVerticalScrollBar();
		vertical.setValue( vertical.getMaximum() );

		//clear input
		messageInput.setText("");

	}

	public static void main(String[] args) {
		/* Set the Nimbus look and feel */
		//<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
		/* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
		 * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
		 */
		try {
			for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
				if ("Windows".equals(info.getName())) {
					javax.swing.UIManager.setLookAndFeel(info.getClassName());
					break;
				}
			}
		} catch (ClassNotFoundException ex) {
			java.util.logging.Logger.getLogger(ClientMsgGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		} catch (InstantiationException ex) {
			java.util.logging.Logger.getLogger(ClientMsgGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		} catch (IllegalAccessException ex) {
			java.util.logging.Logger.getLogger(ClientMsgGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		} catch (javax.swing.UnsupportedLookAndFeelException ex) {
			java.util.logging.Logger.getLogger(ClientMsgGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		}
		//</editor-fold>

		/* Create and display the form */
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				ServerMsgGUI gui = new ServerMsgGUI("ServerMessageGUI");
				gui.setVisible(true);
			}
		});

	}

    /** printMessagesAsync
     * Prints a message to the messages window using a separate thread.
     * @param message The message to print
     */
    public void printMessageAsync(String message){

		new Thread(){

			public void run() {
				messages.append(message + "\n");
			}

		}.start();
	}

    /** sendMessagesAsync
     * Sends a message in another thread
     * @param message The message being sent
     * @param sessionKeys The session keys used to encrypt the message, if needed
     * @param enableConfidential true if Confidentiality is enabled
     * @param enableIntegrity true if Integrity is enabled
     * @param objOut the server's object output stream
     */
    public static void sendMessageAsync(String message, SecretKey[] sessionKeys, boolean enableConfidential, boolean enableIntegrity, ObjectOutputStream objOut){

		new Thread(){
			public void run(){

				try {
					if (!message.equals("") && message != null) {
						
						EncryptedMessage eMsg = new EncryptedMessage(
								message,
								sessionKeys[0], sessionKeys[1],
								enableConfidential, enableIntegrity);
						
						objOut.writeObject(eMsg);
					}



				} catch (IOException e) {
					exit(-1);
					e.printStackTrace();
					return;
				}
			}
		}.start();
	}

    /** enableMessaging
     * @param b true to enable the message input and send button, false to disable
     */
    public void enableMessaging(boolean b){
		messageInput.setEnabled(b);
		sendBtn.setEnabled(b);
	}

    /** enableParams
     * @param b true to enable the checkboxes and parameter confirm button, false to disable
     */
    private void enableParams(boolean b){
		checkConfidential.setEnabled(b);
		checkIntegrity.setEnabled(b);
		checkAuth.setEnabled(b);
		paramConfirmBtn.setEnabled(b);
	}

    /** checkParams
     * @return a truth array consisting of [C,I,A]
     */
    private boolean[] checkParams(){
		boolean[] params = {checkConfidential.isSelected(), checkIntegrity.isSelected(), checkAuth.isSelected()};
		return params;
	}

    /** enableLogin
     * @param b true to enable the user/pass inputs and auth button, false to disable
     */
    private void enableLogin(boolean b){
		usernameInput.setEnabled(b);
		passwordInput.setEnabled(b);
		authBtn.setEnabled(b);
	}

    /** printStatus
     * Prints text (st) to the status window (bottom-left)
     * @param st The string being sent (usually header + text)
     */
    public  void printStatus(String st){
		status.append(st + "\n");
		JScrollBar vertical = jScrollPane2.getVerticalScrollBar();
		vertical.setValue( vertical.getMaximum() );
	}

    /** clearChat
     * Removes any text from the chat window
     */
    public void clearChat(){
		messages.setText("");
	}
}


