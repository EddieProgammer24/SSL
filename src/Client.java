import javax.crypto.*;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.security.*;
import java.util.*;
import java.text.*;
import java.net.*;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Client implements ActionListener {

    private static final int RSA_KEY_SIZE = 1024;
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String DIGEST_ALGORITHM = "SHA-256";
    private static final int SERVER_PORT = 6001;
    private KeyPair keyPair;
    private ExecutorService executorService;


    JTextField text;
    static JPanel a1;
    static Box vertical = Box.createVerticalBox();
    
    static JFrame f = new JFrame();
    
    static DataOutputStream dout;
    
    Client() {
        
        f.setLayout(null);

        // Initialize the executor service
        executorService = Executors.newFixedThreadPool(2);
        
        JPanel p1 = new JPanel();
        p1.setBackground(new Color(7, 94, 84));
        p1.setBounds(0, 0, 450, 70);
        p1.setLayout(null);
        f.add(p1);

        JLabel name = new JLabel("Client");
        name.setBounds(110, 15, 100, 18);
        name.setForeground(Color.WHITE);
        name.setFont(new Font("SAN_SERIF", Font.BOLD, 18));
        p1.add(name);
        
        JLabel status = new JLabel("Active Now");
        status.setBounds(110, 35, 100, 18);
        status.setForeground(Color.WHITE);
        status.setFont(new Font("SAN_SERIF", Font.BOLD, 14));
        p1.add(status);
        
        a1 = new JPanel();
        a1.setBounds(5, 75, 440, 570);
        f.add(a1);

        // Create a button for attaching files
        JButton attachButton = new JButton(new ImageIcon(ClassLoader.getSystemResource("icons/attach.png")));
        attachButton.setBounds(5, 655, 40, 40);
        attachButton.addActionListener(e -> {
            // Open a file chooser dialog to select a file
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showOpenDialog(f);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                // Here, you can handle the selected file (e.g., send it to the server)
                System.out.println("Selected file: " + selectedFile.getAbsolutePath());
            }
        });
        f.add(attachButton);


        text = new JTextField();
        text.setBounds(50, 655, 265, 40); // Adjusted the position to accommodate the attach button
        text.setFont(new Font("SAN_SERIF", Font.PLAIN, 16));
        f.add(text);

        JButton send = new JButton("Send");
        send.setBounds(320, 655, 123, 40);
        send.setBackground(new Color(7, 94, 84));
        send.setForeground(Color.WHITE);
        send.addActionListener(this);
        send.setFont(new Font("SAN_SERIF", Font.PLAIN, 16));
        f.add(send);
        
        f.setSize(450, 700);
        f.setLocation(800, 50);
        f.setLocationRelativeTo(null);
        f.setUndecorated(true);
        f.getContentPane().setBackground(Color.WHITE);
        
        f.setVisible(true);
    }
    
    public void actionPerformed(ActionEvent ae) {
        try {
            String out = text.getText();
            generateRSAKeyPair();

            // Generate symmetric session key for message encryption
            SecretKey sessionKey = generateAESKey();

            // Encrypt the message with the session key
            byte[] encryptedData = encryptWithAES(out, sessionKey);

            // Encrypt the session key with the recipient's public key
            byte[] encryptedSessionKey = encryptWithRSAPublicKey(sessionKey.getEncoded());

            // Send the encrypted message and encrypted session key to the server
            sendEncryptedMessage(out, encryptedData, encryptedSessionKey, keyPair.getPublic().getEncoded());

            // Clear the text field after sending the message
            text.setText("");


            JPanel p2 = formatLabel(out);

            a1.setLayout(new BorderLayout());

            JPanel right = new JPanel(new BorderLayout());
            right.add(p2, BorderLayout.LINE_END);
            vertical.add(right);
            vertical.add(Box.createVerticalStrut(15));

            a1.add(vertical, BorderLayout.PAGE_START);

            generateRSAKeyPair();

            dout.writeUTF(out);

            text.setText("");


            f.repaint();
            f.invalidate();
            f.validate();

            // Perform encryption and other necessary operations
            handleEncryptAction(out);
            text.setText(""); // Clear the text field after sending the message
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Modify the sendToServer method to include encryption
    private void sendEncryptedMessage(String originalMessage, byte[] encryptedData, byte[] encryptedSessionKey, byte[] publicKey) {
        executorService.submit(() -> {
            try {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket socket = (SSLSocket) factory.createSocket("localhost", SERVER_PORT);

                ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
                outputStream.writeObject("User 1: " + originalMessage);
                outputStream.writeObject("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedData));
                outputStream.writeObject("Encrypted Session Key: " + Base64.getEncoder().encodeToString(encryptedSessionKey));
                outputStream.writeObject("Public Key: " + Base64.getEncoder().encodeToString(publicKey));

                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
                String serverResponse = (String) inputStream.readObject();
                System.out.println(serverResponse);

                outputStream.close();
                inputStream.close();
                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
    private void sendToServer(String originalMessage, byte[] encryptedData, byte[] publicKey) {
        executorService.submit(() -> {
            try {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket socket = (SSLSocket) factory.createSocket("localhost", SERVER_PORT);

                ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
                outputStream.writeObject("User 1: " + originalMessage);
                outputStream.writeObject("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedData));
                outputStream.writeObject("Public Key: " + Base64.getEncoder().encodeToString(publicKey));

                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
                String serverResponse = (String) inputStream.readObject();
                System.out.println(serverResponse);

                outputStream.close();
                inputStream.close();
                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }

        });
    }

    private void handleEncryptAction(String originalMessage) {
        try {
            // Symmetric Key Encryption using AES
            SecretKey secretKey = generateAESKey();
            byte[] encryptedSecret = encryptWithAES(originalMessage, secretKey);

            // Data Encryption and Decryption using RSA
            byte[] encryptedData = encryptWithRSAPublicKey(encryptedSecret);
            String decryptedSecret = decryptWithRSAPrivateKey(encryptedData);

            // Message Digest
            byte[] digest = generateDigest(originalMessage);

            // Digital Signatures
            byte[] signature = signData(originalMessage.getBytes());
            boolean isVerified = verifySignature(originalMessage.getBytes(), signature);

            // Update the console
            System.out.println("Original Message: " + originalMessage);
            System.out.println("Encrypted Secret: " + Base64.getEncoder().encodeToString(encryptedSecret));
            System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedData));
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            System.out.println("Decrypted Secret: " + decryptedSecret);
            System.out.println("Message Digest: " + Base64.getEncoder().encodeToString(digest));
            System.out.println("Signature Verified: " + isVerified);

            // Send the encrypted data to the server
            sendToServer(originalMessage, encryptedData, keyPair.getPublic().getEncoded());

        } catch (Exception ignored) {
            ignored.printStackTrace();
        }
    }

    private void generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(RSA_KEY_SIZE);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        return keyGenerator.generateKey();
    }

    private byte[] encryptWithAES(String data, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data.getBytes());
    }

    private byte[] encryptWithRSAPublicKey(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(data);
    }

    private String decryptWithRSAPrivateKey(byte[] encryptedData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }
    private byte[] generateDigest(String data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
        return messageDigest.digest(data.getBytes());
    }

    private byte[] signData(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    private boolean verifySignature(byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(keyPair.getPublic());
        sig.update(data);
        return sig.verify(signature);
    }


    public static JPanel formatLabel(String out) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        
        JLabel output = new JLabel("<html><p style=\"width: 150px\">" + out + "</p></html>");
        output.setFont(new Font("Tahoma", Font.PLAIN, 16));
        output.setBackground(new Color(37, 211, 102));
        output.setOpaque(true);
        output.setBorder(new EmptyBorder(15, 15, 15, 50));
        
        panel.add(output);
        
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm");
        
        JLabel time = new JLabel();
        time.setText(sdf.format(cal.getTime()));
        
        panel.add(time);
        
        return panel;
    }

    public static void main(String[] args) {
        new Client();

        try {
            Socket s = new Socket("127.0.0.1", 6001);
            System.out.println("Server started. Listening on port " + s.getLocalPort() + "...");
            DataInputStream din = new DataInputStream(s.getInputStream());
            dout = new DataOutputStream(s.getOutputStream());


            while(true) {
                a1.setLayout(new BorderLayout());
                String msg = din.readUTF();
                JPanel panel = formatLabel(msg);

                JPanel left = new JPanel(new BorderLayout());
                left.add(panel, BorderLayout.LINE_START);
                vertical.add(left);

                vertical.add(Box.createVerticalStrut(15));
                a1.add(vertical, BorderLayout.PAGE_START);

                f.validate();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
