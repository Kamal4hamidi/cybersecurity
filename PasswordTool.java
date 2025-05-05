import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.Base64;

public class PasswordTool {
    private static final String VAULT_FILE = "passwords.vault";
    private static final String KEY_FILE = "secret.key";
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16;
    private static SecretKey secretKey;

    static {
        try {
            initializeKey();
        } catch (Exception e) {
            throw new RuntimeException("PasswordTool initialization failed", e);
        }
    }

    private static void initializeKey() throws Exception {
        Path keyPath = Paths.get(KEY_FILE);
        
        if (Files.exists(keyPath)) {
            try {
                byte[] keyBytes = Files.readAllBytes(keyPath);
                secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            } catch (IOException e) {
                throw new Exception("Failed to read key file: " + e.getMessage());
            }
        } else {
            try {
                // Create parent directories if needed
                Files.createDirectories(keyPath.getParent());
                
                KeyGenerator keyGen = KeyGenerator.getInstance(KEY_ALGORITHM);
                keyGen.init(256);
                secretKey = keyGen.generateKey();
                
                Files.write(keyPath, secretKey.getEncoded(), 
                           StandardOpenOption.CREATE, 
                           StandardOpenOption.WRITE, 
                           StandardOpenOption.TRUNCATE_EXISTING);
            } catch (Exception e) {
                throw new Exception("Failed to generate and save key: " + e.getMessage());
            }
        }
    }

    public static void savePassword(String id, String password) throws Exception {
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("ID cannot be null or empty");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        Map<String, String> vault = loadVault();
        vault.put(id, encrypt(password));
        saveVault(vault);
    }

    public static String getPassword(String id) throws Exception {
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("ID cannot be null or empty");
        }
        
        Map<String, String> vault = loadVault();
        String encrypted = vault.get(id);
        return encrypted != null ? decrypt(encrypted) : null;
    }

    private static String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }

    private static String decrypt(String encrypted) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encrypted);
        byte[] iv = Arrays.copyOfRange(combined, 0, IV_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(combined, IV_SIZE, combined.length);
        
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        
        return new String(cipher.doFinal(ciphertext), "UTF-8");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> loadVault() throws Exception {
        Path vaultPath = Paths.get(VAULT_FILE);
        if (!Files.exists(vaultPath)) {
            return new HashMap<>();
        }
        
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(VAULT_FILE))) {
            return (Map<String, String>) ois.readObject();
        } catch (Exception e) {
            throw new Exception("Failed to load password vault: " + e.getMessage());
        }
    }

    private static void saveVault(Map<String, String> vault) throws Exception {
        Path vaultPath = Paths.get(VAULT_FILE);
        Files.createDirectories(vaultPath.getParent());
        
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(VAULT_FILE))) {
            oos.writeObject(vault);
        } catch (Exception e) {
            throw new Exception("Failed to save password vault: " + e.getMessage());
        }
    }

        // Ajoutez cette méthode à votre classe PasswordTool.java

    /**
     * Retourne tous les mots de passe stockés dans le coffre
     * @return Une Map contenant les identifiants et mots de passe (chiffrés)
     * @throws Exception En cas d'erreur lors du chargement du coffre
     */
    public static Map<String, String> getAllPasswords() throws Exception {
        return new HashMap<>(loadVault());
    }
}