import javax.swing.SwingUtilities;

public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // Lance l'interface utilisateur Swing
                EncryptionApp app = new EncryptionApp();
                app.setVisible(true);
            }
        });
    }
}
