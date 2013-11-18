package cryptography;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.UIManager;

/**
 * @author lindelof
 * @since Nov 15, 2013
 *
 */
public abstract class Utility {

    Editor editor;
    public File dir;
    public String username, password;

    /**
     * @wbp.parser.entryPoint
     */
    public Utility(Editor e) {
        editor = e;
    }

    public abstract void create(String file_name, String user_name, String password) throws Exception;

    public abstract String findUser(String file_name) throws Exception;

    public abstract int length(String file_name, String password) throws Exception;

    public abstract byte[] read(String file_name, int starting_position, int len, String password) throws Exception;

    public abstract void write(String file_name, int starting_position, byte[] content, String password) throws Exception;

    //public abstract void save(String file_name, String content, String password) throws Exception;
    public abstract boolean check_integrity(String file_name, String password) throws Exception;

    public abstract void cut(String file_name, int len, String password) throws Exception;

    public void set_username_password() {
        JPanel loginPanel = new JPanel();
        loginPanel.setBorder(UIManager.getBorder("TextPane.border"));
        GridBagLayout gbl_loginPanel = new GridBagLayout();
        gbl_loginPanel.rowWeights = new double[]{1.0, 0.0};
        gbl_loginPanel.columnWeights = new double[]{1.0, 0.0};
        loginPanel.setLayout(gbl_loginPanel);
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints. VERTICAL;
        
        JLabel username_tag = new JLabel();
        JTextField username_field = new JTextField("",12);

        username_tag.setText("username");
        GridBagConstraints gbc_username_tag = new GridBagConstraints();
        gbc_username_tag.anchor = GridBagConstraints.WEST;
        gbc_username_tag.gridy = 0;
        gbc_username_tag.gridx = 0;
        loginPanel.add(username_tag, gbc_username_tag);
        GridBagConstraints gbc_username_field = new GridBagConstraints();
        gbc_username_field.fill = GridBagConstraints.HORIZONTAL;
        gbc_username_field.weightx = 0.5;
        gbc_username_field.gridy = 0;
        gbc_username_field.gridx = 1;
        loginPanel.add(username_field, gbc_username_field);

        JLabel password_tag = new JLabel();
        JPasswordField password_field = new JPasswordField("",12);

        password_tag.setText("password");
        GridBagConstraints gbc_password_tag = new GridBagConstraints();
        gbc_password_tag.anchor = GridBagConstraints.WEST;
        gbc_password_tag.gridy = 1;
        gbc_password_tag.gridx = 0;
        loginPanel.add(password_tag, gbc_password_tag);
        GridBagConstraints gbc_password_field = new GridBagConstraints();
        gbc_password_field.fill = GridBagConstraints.HORIZONTAL;
        gbc_password_field.gridy = 1;
        gbc_password_field.gridx = 1;
        loginPanel.add(password_field, gbc_password_field);

        int okCxl = JOptionPane.showConfirmDialog(null, loginPanel, "Enter Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (okCxl == JOptionPane.OK_OPTION) {
            this.password = new String(password_field.getPassword());
            this.username = new String(username_field.getText());
            
            if(this.username == null || this.username.length() == 0 || this.password == null || this.password.length() == 0){
            	JOptionPane.showMessageDialog(this.editor, "Check your username and password.");
            	set_username_password();
            }

        }else if(okCxl == JOptionPane.CANCEL_OPTION){
        	//PrintStream ps = new PrintStream(currentProcess.getOutputStream());
        	System.exit(0);
        }
    }

    public byte[] read_from_file(File file) throws Exception {
        DataInputStream in = new DataInputStream(
                new BufferedInputStream(
                new FileInputStream(file)));

        int size = in.available();

        byte[] toR = new byte[size];

        in.read(toR);

        in.close();
        return toR;

    }

    public void save_to_file(byte[] s, File file) throws Exception {
        if (file == null) {
            return;
        }
        DataOutputStream out = new DataOutputStream(new FileOutputStream(file));
        out.write(s);
        out.close();

    }

    public File set_dir() {
        JFileChooser fileChooser  = new JFileChooser(System.getProperty("user.dir"));
        fileChooser.setFileSelectionMode(fileChooser.DIRECTORIES_ONLY);
        if (fileChooser.showOpenDialog(editor) == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();


        } else {

            return null;
        }
    }

    public static byte[] encript_AES(byte[] plainText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");


        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(plainText);
        //String ret = byteArray2String(ciphertext);

        return ciphertext;

        //String encryptedString;
        //encryptedString = ret;//new String(ciphertext);

        //return encryptedString;
    }

    public static byte[] decript_AES(byte[] cypherText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");


        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(cypherText);
        //String decryptedString = new String(cipher.doFinal(cypherText), "UTF-8");
        //return decryptedString;
    }

    public static byte[] hash_SHA256(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash1 = digest.digest(message);
        return hash1;
    }

    public static byte[] hash_SHA384(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-384");
        byte[] hash1 = digest.digest(message);
        return hash1;
    }

    public static byte[] hash_SHA512(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hash1 = digest.digest(message);
        return hash1;
    }

    public static String byteArray2String(byte[] array) {
        String ret = "";
        for (int i = 0; i < array.length; i++) {
            if (array[i] < 0)
            {
                javax.swing.JOptionPane.showMessageDialog(null, "Error: cannot convert negative number " + array[i] + " into character");
                //return "";
            }
            ret += (char) array[i];
        }

        return ret;
    }
}
