import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.Arrays;

public class AESFileEncryption {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16;
    private static final int BUFFER_SIZE = 8192;

    public static SecretKeySpec getKey(String password) throws Exception {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes("UTF-8"));
        return new SecretKeySpec(key, "AES");
    }

    public static void encryptFile(String inputPath, String outputPath, SecretKeySpec key) throws Exception {
        validatePaths(inputPath, outputPath);
        
        File tempFile = File.createTempFile("aes_encrypt_", ".tmp", new File(outputPath).getParentFile());
        
        try (FileInputStream fis = new FileInputStream(inputPath);
             FileOutputStream fos = new FileOutputStream(tempFile)) {
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[IV_SIZE];
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            
            fos.write(iv);
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) fos.write(output);
            }
            
            byte[] output = cipher.doFinal();
            if (output != null) fos.write(output);
            
            // Only rename if everything succeeded
            Files.move(tempFile.toPath(), Paths.get(outputPath), StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            tempFile.delete();
            throw e;
        }
    }

    public static void decryptFile(String inputPath, String outputPath, SecretKeySpec key) throws Exception {
        validatePaths(inputPath, outputPath);
        
        File tempFile = File.createTempFile("aes_decrypt_", ".tmp", new File(outputPath).getParentFile());
        
        try (FileInputStream fis = new FileInputStream(inputPath);
             FileOutputStream fos = new FileOutputStream(tempFile)) {
            
            byte[] iv = new byte[IV_SIZE];
            if (fis.read(iv) != IV_SIZE) {
                throw new IOException("Invalid IV in encrypted file");
            }
            
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) fos.write(output);
            }
            
            byte[] output = cipher.doFinal();
            if (output != null) fos.write(output);
            
            Files.move(tempFile.toPath(), Paths.get(outputPath), StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            tempFile.delete();
            throw e;
        }
    }

    private static void validatePaths(String inputPath, String outputPath) throws IOException {
        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            throw new FileNotFoundException("Input file not found: " + inputPath);
        }
        if (!inputFile.canRead()) {
            throw new IOException("Cannot read input file: " + inputPath);
        }
        
        File outputFile = new File(outputPath);
        File parentDir = outputFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            throw new IOException("Output directory does not exist: " + parentDir.getAbsolutePath());
        }
        if (outputFile.exists() && !outputFile.canWrite()) {
            throw new IOException("Cannot write to output file: " + outputPath);
        }
    }
}
