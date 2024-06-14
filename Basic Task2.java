import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.io.*;
public class PasswordManager {
    private static final String ALGORITHM = "JAVA";
    private static final int KEY_SIZE = 128;
    private static final String PASSWORD_FILE = "passwords.dat";
    private SecretKey secretKey;
    private Map<String, String> passwordMap;

    public PasswordManager() {
        this.secretKey = generateSecretKey();
        this.passwordMap = new HashMap<>();
        loadPasswords();
    }

    public static void main(String[] args) {
        PasswordManager manager = new PasswordManager();
        Scanner scanner = new Scanner(System.in);
        int choice;

        do {
            System.out.println("Password Manager Menu:");
            System.out.println("1. Generate and save a password");
            System.out.println("2. Retrieve a password");
            System.out.println("3. List all accounts");
            System.out.println("4. Exit");
            System.out.print("Enter your choice: ");
            choice = scanner.nextInt();
            scanner.nextLine();  // Consume newline left-over

            switch (choice) {
                case 1:
                    manager.addPassword(scanner);
                    break;
                case 2:
                    manager.getPassword(scanner);
                    break;
                case 3:
                    manager.listAccounts();
                    break;
                case 4:
                    System.out.println("Exiting the application.");
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        } while (choice != 4);

        scanner.close();
        manager.savePasswords();
    }

    private void addPassword(Scanner scanner) {
        System.out.print("Enter the account name: ");
        String account = scanner.nextLine();
        String password = generatePassword(16);
        String encryptedPassword = encryptPassword(password);
        passwordMap.put(account, encryptedPassword);
        System.out.println("Generated password: " + password);
    }

    private void getPassword(Scanner scanner) {
        System.out.print("Enter the account name: ");
        String account = scanner.nextLine();
        String encryptedPassword = passwordMap.get(account);
        if (encryptedPassword != null) {
            String password = decryptPassword(encryptedPassword);
            System.out.println("Retrieved password: " + password);
        } else {
            System.out.println("Account not found.");
        }
    }

    private void listAccounts() {
        if (passwordMap.isEmpty()) {
            System.out.println("No accounts available.");
        } else {
            System.out.println("Accounts:");
            for (String account : passwordMap.keySet()) {
                System.out.println(account);
            }
        }
    }

    private SecretKey generateSecretKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Error generating secret key", e);
        }
    }

    private String generatePassword(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }

    private String encryptPassword(String password) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(password.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting password", e);
        }
    }

    private String decryptPassword(String encryptedPassword) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting password", e);
        }
    }

    private void savePasswords() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PASSWORD_FILE))) {
            oos.writeObject(passwordMap);
        } catch (IOException e) {
            System.err.println("Error saving passwords: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void loadPasswords() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PASSWORD_FILE))) {
            passwordMap = (Map<String, String>) ois.readObject();
        } catch (FileNotFoundException e) {
            // Ignore, file will be created on save
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error loading passwords: " + e.getMessage());
        }
    }
}
