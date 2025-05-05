import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.swing.*;
import java.awt.*;
import org.json.simple.*;

public class PasswordExporter {
    private static final String CSV_HEADER = "ID,Password\n";
    
    /**
     * Exporte les mots de passe vers un fichier CSV
     * @param outputPath Chemin du fichier de sortie
     * @param decrypt Option pour décrypter les mots de passe lors de l'export
     * @throws Exception En cas d'erreur pendant l'exportation
     */
    public static void exportToCSV(String outputPath, boolean decrypt) throws Exception {
        Map<String, String> passwords = PasswordTool.getAllPasswords();
        
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(outputPath))) {
            writer.write(CSV_HEADER);
            
            for (Map.Entry<String, String> entry : passwords.entrySet()) {
                String id = entry.getKey();
                String password = entry.getValue();
                
                if (decrypt) {
                    // Utilise la méthode déjà disponible pour décrypter
                    password = PasswordTool.getPassword(id);
                }
                
                // Échapper les virgules et les guillemets pour le format CSV
                id = escapeCSV(id);
                password = escapeCSV(password);
                
                writer.write(id + "," + password + "\n");
            }
        } catch (IOException e) {
            throw new Exception("Erreur lors de l'exportation CSV: " + e.getMessage());
        }
    }
    
    /**
     * Exporte les mots de passe vers un fichier JSON
     * @param outputPath Chemin du fichier de sortie
     * @param decrypt Option pour décrypter les mots de passe lors de l'export
     * @throws Exception En cas d'erreur pendant l'exportation
     */
    public static void exportToJSON(String outputPath, boolean decrypt) throws Exception {
        Map<String, String> passwords = PasswordTool.getAllPasswords();
        JSONObject json = new JSONObject();
        
        for (Map.Entry<String, String> entry : passwords.entrySet()) {
            String id = entry.getKey();
            String password = entry.getValue();
            
            if (decrypt) {
                // Utilise la méthode déjà disponible pour décrypter
                password = PasswordTool.getPassword(id);
            }
            
            json.put(id, password);
        }
        
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(json.toJSONString());
        } catch (IOException e) {
            throw new Exception("Erreur lors de l'exportation JSON: " + e.getMessage());
        }
    }
    
    /**
     * Échappe les caractères spéciaux pour le format CSV
     * @param value La valeur à échapper
     * @return La valeur échappée
     */
    private static String escapeCSV(String value) {
        if (value == null) return "";
        
        // Si contient virgule, guillemet ou retour à la ligne, mettre entre guillemets
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            // Doubler les guillemets pour les échapper
            value = value.replace("\"", "\"\"");
            value = "\"" + value + "\"";
        }
        
        return value;
    }
    
    /**
     * Crée un dialogue pour exporter les mots de passe
     * @param parent La fenêtre parente
     * @return true si l'export a réussi, false sinon
     */
    public static boolean showExportDialog(JFrame parent) {
        JDialog dialog = new JDialog(parent, "Export des mots de passe", true);
        dialog.setLayout(new BorderLayout());
        dialog.setSize(450, 200);
        dialog.setLocationRelativeTo(parent);
        
        JPanel optionsPanel = new JPanel(new GridLayout(0, 1));
        JRadioButton csvRadio = new JRadioButton("Format CSV", true);
        JRadioButton jsonRadio = new JRadioButton("Format JSON", false);
        ButtonGroup formatGroup = new ButtonGroup();
        formatGroup.add(csvRadio);
        formatGroup.add(jsonRadio);
        
        JCheckBox decryptCheck = new JCheckBox("Exporter en clair (non chiffré)", false);
        JLabel warningLabel = new JLabel("⚠️ Attention: Exporter les mots de passe en clair présente un risque de sécurité!");
        warningLabel.setForeground(Color.RED);
        
        optionsPanel.add(csvRadio);
        optionsPanel.add(jsonRadio);
        optionsPanel.add(decryptCheck);
        optionsPanel.add(warningLabel);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton exportButton = new JButton("Exporter");
        JButton cancelButton = new JButton("Annuler");
        buttonPanel.add(exportButton);
        buttonPanel.add(cancelButton);
        
        dialog.add(optionsPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        final boolean[] success = {false};
        
        exportButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Enregistrer le fichier d'export");
            
            // Définir l'extension de fichier selon le format sélectionné
            if (csvRadio.isSelected()) {
                fileChooser.setSelectedFile(new File("passwords_export.csv"));
            } else {
                fileChooser.setSelectedFile(new File("passwords_export.json"));
            }
            
            if (fileChooser.showSaveDialog(dialog) == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                try {
                    if (csvRadio.isSelected()) {
                        exportToCSV(selectedFile.getAbsolutePath(), decryptCheck.isSelected());
                    } else {
                        exportToJSON(selectedFile.getAbsolutePath(), decryptCheck.isSelected());
                    }
                    JOptionPane.showMessageDialog(dialog, 
                        "Export réussi vers: " + selectedFile.getAbsolutePath(), 
                        "Succès", JOptionPane.INFORMATION_MESSAGE);
                    success[0] = true;
                    dialog.dispose();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(dialog, 
                        "Erreur lors de l'export: " + ex.getMessage(), 
                        "Erreur", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        decryptCheck.addActionListener(e -> {
            if (decryptCheck.isSelected()) {
                int result = JOptionPane.showConfirmDialog(dialog, 
                    "Êtes-vous sûr de vouloir exporter les mots de passe en clair?\n" +
                    "Cela peut représenter un risque de sécurité important.",
                    "Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (result != JOptionPane.YES_OPTION) {
                    decryptCheck.setSelected(false);
                }
            }
        });
        
        dialog.setVisible(true);
        return success[0];
    }
}