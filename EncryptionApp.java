import javax.swing.*;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.nio.file.*;

public class EncryptionApp extends JFrame {
    private JTextField passwordField;
    private JTextField inputFileField, encryptedFileField, decryptedFileField;
    private JButton inputBrowseButton, encryptedBrowseButton, decryptedBrowseButton;
    private JButton encryptButton, decryptButton;
    private JButton savePwdButton, loadPwdButton;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    private JButton exportButton;

    public EncryptionApp() {
        setTitle("AES File Encryption Tool");
        setSize(700, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Password Field
        gbc.gridx = 0; gbc.gridy = 0;
        add(new JLabel("Password:"), gbc);
        passwordField = new JPasswordField();
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1;
        add(passwordField, gbc);

        // Input File
        gbc.gridy++; gbc.gridx = 0; gbc.gridwidth = 1; gbc.weightx = 0;
        add(new JLabel("Input File:"), gbc);
        inputFileField = new JTextField();
        gbc.gridx = 1; gbc.weightx = 1;
        add(inputFileField, gbc);
        inputBrowseButton = new JButton("Browse");
        gbc.gridx = 2; gbc.weightx = 0;
        add(inputBrowseButton, gbc);

        // Encrypted File
        gbc.gridy++; gbc.gridx = 0;
        add(new JLabel("Encrypted File:"), gbc);
        encryptedFileField = new JTextField();
        gbc.gridx = 1;
        add(encryptedFileField, gbc);
        encryptedBrowseButton = new JButton("Browse");
        gbc.gridx = 2;
        add(encryptedBrowseButton, gbc);

        // Decrypted File
        gbc.gridy++; gbc.gridx = 0;
        add(new JLabel("Decrypted File:"), gbc);
        decryptedFileField = new JTextField();
        gbc.gridx = 1;
        add(decryptedFileField, gbc);
        decryptedBrowseButton = new JButton("Browse");
        gbc.gridx = 2;
        add(decryptedBrowseButton, gbc);

        // Password Management Buttons
        JPanel pwdPanel = new JPanel(new FlowLayout());
        savePwdButton = new JButton("Save Password");
        loadPwdButton = new JButton("Load Password");
        pwdPanel.add(savePwdButton);
        pwdPanel.add(loadPwdButton);
        gbc.gridy++; gbc.gridx = 0; gbc.gridwidth = 3;
        add(pwdPanel, gbc);

        // Action Buttons
        JPanel actionPanel = new JPanel(new FlowLayout());
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        exportButton = new JButton("Exporter les mots de passe");
        actionPanel.add(encryptButton);
        actionPanel.add(decryptButton);
        actionPanel.add(exportButton);
        gbc.gridy++;
        add(actionPanel, gbc);

        // Progress Bar
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        gbc.gridy++;
        add(progressBar, gbc);

        // Status Label
        statusLabel = new JLabel(" ", SwingConstants.CENTER);
        gbc.gridy++;
        add(statusLabel, gbc);

        setupEventHandlers();
    }
    private void setupEventHandlers() {
        inputBrowseButton.addActionListener(e -> {
            chooseFile(inputFileField);
            loadPasswordForFile();
            suggestOutputFilename(inputFileField.getText(), encryptedFileField, ".enc");
        });
        
        encryptedBrowseButton.addActionListener(e -> {
            chooseFile(encryptedFileField);
            suggestOutputFilename(encryptedFileField.getText(), decryptedFileField, ".dec");
        });

        exportButton.addActionListener(e -> {
            PasswordExporter.showExportDialog(this);
        });
        
        decryptedBrowseButton.addActionListener(e -> chooseSaveFile(decryptedFileField));

        savePwdButton.addActionListener(e -> savePasswordForFile());
        loadPwdButton.addActionListener(e -> loadPasswordForFile());

        encryptButton.addActionListener(e -> new Thread(this::handleEncryption).start());
        decryptButton.addActionListener(e -> new Thread(this::handleDecryption).start());
    }

    private void handleEncryption() {
        setUiEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        
        try {
            validateInputs(true);
            
            if (!isPasswordStrong(passwordField.getText())) {
                throw new Exception("Password is too weak. Use at least 8 characters.");
            }
            
            SecretKeySpec key = AESFileEncryption.getKey(passwordField.getText());
            AESFileEncryption.encryptFile(
                inputFileField.getText(),
                encryptedFileField.getText(),
                key
            );
            
            savePasswordForFile();
            statusLabel.setText("Encryption successful!");
        } catch (Exception ex) {
            statusLabel.setText("Encryption failed: " + ex.getMessage());
        } finally {
            progressBar.setVisible(false);
            setUiEnabled(true);
        }
    }

    private void handleDecryption() {
        setUiEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        
        try {
            validateInputs(false);
            SecretKeySpec key = AESFileEncryption.getKey(passwordField.getText());
            AESFileEncryption.decryptFile(
                encryptedFileField.getText(),
                decryptedFileField.getText(),
                key
            );
            statusLabel.setText("Decryption successful!");
        } catch (Exception ex) {
            statusLabel.setText("Decryption failed: " + ex.getMessage());
        } finally {
            progressBar.setVisible(false);
            setUiEnabled(true);
        }
    }

    private void savePasswordForFile() {
        try {
            if (inputFileField.getText().isEmpty()) {
                throw new Exception("No input file selected");
            }
            
            PasswordTool.savePassword(
                "file_" + inputFileField.getText(),
                passwordField.getText()
            );
            statusLabel.setText("Password saved for: " + inputFileField.getText());
        } catch (Exception e) {
            statusLabel.setText("Password save failed: " + e.getMessage());
        }
    }

    private void loadPasswordForFile() {
        try {
            if (inputFileField.getText().isEmpty()) {
                throw new Exception("No input file selected");
            }
            
            String password = PasswordTool.getPassword("file_" + inputFileField.getText());
            if (password != null) {
                passwordField.setText(password);
                statusLabel.setText("Password loaded for: " + inputFileField.getText());
            } else {
                statusLabel.setText("No password found for this file");
            }
        } catch (Exception e) {
            statusLabel.setText("Password load failed: " + e.getMessage());
        }
    }

    private void validateInputs(boolean isEncrypt) throws Exception {
        if (passwordField.getText().isEmpty()) {
            throw new Exception("Password cannot be empty");
        }
        
        String inputPath = isEncrypt ? inputFileField.getText() : encryptedFileField.getText();
        if (inputPath == null || inputPath.trim().isEmpty()) {
            throw new Exception("Input file path is empty");
        }
        
        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            throw new Exception("Input file does not exist at: " + inputFile.getAbsolutePath());
        }
        if (!inputFile.canRead()) {
            throw new Exception("Cannot read input file - check permissions");
        }
        
        String outputPath = isEncrypt ? encryptedFileField.getText() : decryptedFileField.getText();
        if (outputPath == null || outputPath.trim().isEmpty()) {
            throw new Exception("Output file path is empty");
        }
        
        File outputFile = new File(outputPath);
        if (outputFile.exists() && !outputFile.canWrite()) {
            throw new Exception("Cannot write to output file - check permissions");
        }
        
        File parentDir = outputFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            throw new Exception("Output directory does not exist: " + parentDir.getAbsolutePath());
        }
    }

    private void chooseFile(JTextField target) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select File");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            target.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void chooseSaveFile(JTextField target) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save File");
        
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            if (selected.exists()) {
                int confirm = JOptionPane.showConfirmDialog(this, 
                    "File exists. Overwrite?", "Confirm", JOptionPane.YES_NO_OPTION);
                if (confirm != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            target.setText(selected.getAbsolutePath());
        }
    }

    private void suggestOutputFilename(String inputPath, JTextField outputField, String suffix) {
        if (inputPath != null && !inputPath.isEmpty()) {
            File inputFile = new File(inputPath);
            String outputPath = inputFile.getParent() + File.separator + 
                               inputFile.getName() + suffix;
            outputField.setText(outputPath);
        }
    }

    private boolean isPasswordStrong(String password) {
        return password != null && password.length() >= 8;
    }

    private void setUiEnabled(boolean enabled) {
        passwordField.setEnabled(enabled);
        inputFileField.setEnabled(enabled);
        encryptedFileField.setEnabled(enabled);
        decryptedFileField.setEnabled(enabled);
        inputBrowseButton.setEnabled(enabled);
        encryptedBrowseButton.setEnabled(enabled);
        decryptedBrowseButton.setEnabled(enabled);
        savePwdButton.setEnabled(enabled);
        loadPwdButton.setEnabled(enabled);
        exportButton.setEnabled(enabled); // Ajout de cette ligne
        encryptButton.setEnabled(enabled);
        decryptButton.setEnabled(enabled);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            EncryptionApp app = new EncryptionApp();
            app.setVisible(true);
        });
    }
}