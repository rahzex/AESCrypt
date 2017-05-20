/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package aescrypt;

import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileSystemView;

/**
 *
 * @author Rahul Pal
 */
public class CryptUI extends javax.swing.JFrame {

    /**
     * Creates new form CryptUI
     */
    public CryptUI() {
        initComponents();
        //jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
    }
    
    public static File chooseFile(String MODE){
         
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        File selectedFile = null;
        int returnValue = -1;
        
        if(MODE.equals("OPEN")){
            jfc.setDialogTitle("Choose a file");
            returnValue = jfc.showOpenDialog(null);
        }
	if(MODE.equals("SAVE")){
            jfc.setDialogTitle("Choose a folder to save Encrypted file");
            jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            returnValue = jfc.showSaveDialog(null);
        }

	if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFile = jfc.getSelectedFile();
            System.out.println(selectedFile.getAbsolutePath());
	}
        
        return selectedFile;
    }
    

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        textFieldShowEnPath = new javax.swing.JTextField();
        buttonBrowseEn = new javax.swing.JButton();
        buttunEncryptFile = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        textFieldShowDePath = new javax.swing.JTextField();
        buttonBrowseDe = new javax.swing.JButton();
        buttonDecryptFile = new javax.swing.JButton();
        textFieldShowEnSavePath = new javax.swing.JTextField();
        buttonPathToSaveEnFile = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jCheckBox1 = new javax.swing.JCheckBox();
        jLabel6 = new javax.swing.JLabel();
        textFieldShowDeSavePath = new javax.swing.JTextField();
        buttonPathToSaveDeFile = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setResizable(false);
        addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                formPropertyChange(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("HACKED", 0, 28)); // NOI18N
        jLabel1.setText("Welcome To AESCrypt");

        jLabel2.setFont(new java.awt.Font("HACKED", 0, 14)); // NOI18N
        jLabel2.setText("A Simple Tool to Keep your Files Secured");

        jLabel3.setFont(new java.awt.Font("Dialog", 1, 13)); // NOI18N
        jLabel3.setText("Choose a file to Encrypt:");

        buttonBrowseEn.setText("Browse");
        buttonBrowseEn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonBrowseEnActionPerformed(evt);
            }
        });

        buttunEncryptFile.setText("Encrypt File");
        buttunEncryptFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttunEncryptFileActionPerformed(evt);
            }
        });

        jLabel4.setFont(new java.awt.Font("Dialog", 1, 13)); // NOI18N
        jLabel4.setText("Choose a file to Decrypt:");

        buttonBrowseDe.setText("Browse");
        buttonBrowseDe.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonBrowseDeActionPerformed(evt);
            }
        });

        buttonDecryptFile.setText("Decrypt File");
        buttonDecryptFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonDecryptFileActionPerformed(evt);
            }
        });

        buttonPathToSaveEnFile.setText("Browse");
        buttonPathToSaveEnFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonPathToSaveEnFileActionPerformed(evt);
            }
        });

        jLabel5.setFont(new java.awt.Font("Dialog", 1, 13)); // NOI18N
        jLabel5.setText("Choose a folder to save the Encrypted File:");

        jCheckBox1.setText("Delete Original File");

        jLabel6.setFont(new java.awt.Font("Dialog", 1, 13)); // NOI18N
        jLabel6.setText("Choose a folder to save the Decrypted File:");

        buttonPathToSaveDeFile.setText("Browse");
        buttonPathToSaveDeFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonPathToSaveDeFileActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(201, 201, 201)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 254, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 6, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(22, 22, 22)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(textFieldShowEnPath)
                            .addComponent(textFieldShowEnSavePath, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(textFieldShowDePath)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel6)
                                    .addComponent(buttonDecryptFile)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(buttunEncryptFile)
                                        .addGap(18, 18, 18)
                                        .addComponent(jCheckBox1))
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(187, 187, 187)
                                        .addComponent(jLabel2))
                                    .addComponent(jLabel3)
                                    .addComponent(jLabel4)
                                    .addComponent(jLabel5))
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(textFieldShowDeSavePath))))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(buttonBrowseEn)
                        .addComponent(buttonBrowseDe))
                    .addComponent(buttonPathToSaveEnFile)
                    .addComponent(buttonPathToSaveDeFile))
                .addGap(97, 97, 97))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(15, 15, 15)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 15, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(buttonBrowseEn)
                    .addComponent(textFieldShowEnPath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel5)
                .addGap(8, 8, 8)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textFieldShowEnSavePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(buttonPathToSaveEnFile))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(buttunEncryptFile)
                    .addComponent(jCheckBox1))
                .addGap(18, 18, 18)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textFieldShowDePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(buttonBrowseDe))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(textFieldShowDeSavePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(buttonPathToSaveDeFile))
                .addGap(18, 18, 18)
                .addComponent(buttonDecryptFile)
                .addContainerGap(18, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void buttonDecryptFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonDecryptFileActionPerformed
        // TODO add your handling code here:
        if(textFieldShowDePath.getText().equals("") || textFieldShowDeSavePath.getText().equals("")){
            JOptionPane.showMessageDialog(null, "Please choose both files first!");
        }
        else{
            new PasswordDialog(textFieldShowDePath.getText(), textFieldShowDeSavePath.getText(),false,"DECRYPT").setVisible(true);
        }
        
        //reset the path fields to blank
        textFieldShowDePath.setText("");
        textFieldShowDeSavePath.setText("");
    }//GEN-LAST:event_buttonDecryptFileActionPerformed

    private void buttunEncryptFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttunEncryptFileActionPerformed
        // TODO add your handling code here:
        if(textFieldShowEnPath.getText().equals("") || textFieldShowEnSavePath.getText().equals("")){
            JOptionPane.showMessageDialog(null, "Please choose both files first!");
        }
        else{
            System.out.println(jCheckBox1.isSelected());
            new PasswordDialog(textFieldShowEnPath.getText(), textFieldShowEnSavePath.getText(),jCheckBox1.isSelected(),"ENCRYPT").setVisible(true);
        }
        
        //reset the path fields to blank
        textFieldShowEnPath.setText("");
        textFieldShowEnSavePath.setText("");
        
    }//GEN-LAST:event_buttunEncryptFileActionPerformed

    private void buttonBrowseEnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonBrowseEnActionPerformed
        // Browse the file to be encrypted
        File plainFile = chooseFile("OPEN");
        if(plainFile != null)
            textFieldShowEnPath.setText(plainFile.getAbsolutePath());
        
    }//GEN-LAST:event_buttonBrowseEnActionPerformed

    private void buttonBrowseDeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonBrowseDeActionPerformed
        // Browse the file to be decrypted
        File encryptedFile = chooseFile("OPEN");
        if(encryptedFile != null)
            textFieldShowDePath.setText(encryptedFile.getAbsolutePath());
        
    }//GEN-LAST:event_buttonBrowseDeActionPerformed

    private void buttonPathToSaveEnFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonPathToSaveEnFileActionPerformed
        // Browse the folder where the encrypted file is to be saved
        File enFile = chooseFile("SAVE");
        if(enFile != null)
            textFieldShowEnSavePath.setText(enFile.getAbsolutePath());
    }//GEN-LAST:event_buttonPathToSaveEnFileActionPerformed

    private void buttonPathToSaveDeFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonPathToSaveDeFileActionPerformed
        // Browse the folder where the decrypted file is to be saved
        File decryptedFile = chooseFile("SAVE");
        if(decryptedFile != null)
            textFieldShowDeSavePath.setText(decryptedFile.getAbsolutePath());
    }//GEN-LAST:event_buttonPathToSaveDeFileActionPerformed

    private void formPropertyChange(java.beans.PropertyChangeEvent evt) {//GEN-FIRST:event_formPropertyChange
        // TODO add your handling code here:
    }//GEN-LAST:event_formPropertyChange

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(CryptUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(CryptUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(CryptUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(CryptUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new CryptUI().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonBrowseDe;
    private javax.swing.JButton buttonBrowseEn;
    private javax.swing.JButton buttonDecryptFile;
    private javax.swing.JButton buttonPathToSaveDeFile;
    private javax.swing.JButton buttonPathToSaveEnFile;
    private javax.swing.JButton buttunEncryptFile;
    private javax.swing.JCheckBox jCheckBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JTextField textFieldShowDePath;
    private javax.swing.JTextField textFieldShowDeSavePath;
    private javax.swing.JTextField textFieldShowEnPath;
    private javax.swing.JTextField textFieldShowEnSavePath;
    // End of variables declaration//GEN-END:variables
}
