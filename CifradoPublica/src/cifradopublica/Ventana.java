/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cifradopublica;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 *
 * @author daniel
 */
public class Ventana extends javax.swing.JFrame {

    /**
     * Creates new form Ventana
     */
    
    CifradoPublica modelo;
    File archivo;
    
    public Ventana() {
        initComponents();
        modelo = new CifradoPublica();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane2 = new javax.swing.JScrollPane();
        taLog = new javax.swing.JTextArea();
        jMenuBar5 = new javax.swing.JMenuBar();
        jMenu5 = new javax.swing.JMenu();
        opCifrar = new javax.swing.JMenuItem();
        opDecifrar = new javax.swing.JMenuItem();
        opFirmar = new javax.swing.JMenuItem();
        opVerificar = new javax.swing.JMenuItem();
        opSalir = new javax.swing.JMenuItem();
        jMenu6 = new javax.swing.JMenu();
        opClave = new javax.swing.JMenuItem();
        opGenerar = new javax.swing.JMenuItem();
        opVeractual = new javax.swing.JMenuItem();
        jMenu1 = new javax.swing.JMenu();
        ayudaDaniel = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Practica 3 Daniel Correa");
        setSize(new java.awt.Dimension(500, 500));

        taLog.setEditable(false);
        taLog.setColumns(20);
        taLog.setRows(5);
        jScrollPane2.setViewportView(taLog);

        getContentPane().add(jScrollPane2, java.awt.BorderLayout.CENTER);

        jMenu5.setText("Archivo");

        opCifrar.setText("Cifrar");
        opCifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opCifrarActionPerformed(evt);
            }
        });
        jMenu5.add(opCifrar);

        opDecifrar.setText("Decifrar");
        opDecifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opDecifrarActionPerformed(evt);
            }
        });
        jMenu5.add(opDecifrar);

        opFirmar.setText("Firmar");
        opFirmar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opFirmarActionPerformed(evt);
            }
        });
        jMenu5.add(opFirmar);

        opVerificar.setText("Verificar Firma");
        opVerificar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opVerificarActionPerformed(evt);
            }
        });
        jMenu5.add(opVerificar);

        opSalir.setText("Salir");
        opSalir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opSalirActionPerformed(evt);
            }
        });
        jMenu5.add(opSalir);

        jMenuBar5.add(jMenu5);

        jMenu6.setText("Claves");

        opClave.setText("Opciones de Clave");
        opClave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opClaveActionPerformed(evt);
            }
        });
        jMenu6.add(opClave);

        opGenerar.setText("Generar nuevas claves");
        opGenerar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opGenerarActionPerformed(evt);
            }
        });
        jMenu6.add(opGenerar);

        opVeractual.setText("Ver claves actuales");
        opVeractual.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opVeractualActionPerformed(evt);
            }
        });
        jMenu6.add(opVeractual);

        jMenuBar5.add(jMenu6);

        jMenu1.setText("Ayuda");

        ayudaDaniel.setText("Acerca de ...");
        ayudaDaniel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ayudaDanielActionPerformed(evt);
            }
        });
        jMenu1.add(ayudaDaniel);

        jMenuBar5.add(jMenu1);

        setJMenuBar(jMenuBar5);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void cargarArchivo(){
        String cwd = System.getProperty("user.dir");
        final JFileChooser jfc = new JFileChooser(cwd);
        if (jfc.showOpenDialog(this) !=JFileChooser.APPROVE_OPTION) return;
        archivo = jfc.getSelectedFile();
    }
    
    private void ayudaDanielActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ayudaDanielActionPerformed
        // TODO add your handling code here:
        JOptionPane.showMessageDialog(rootPane, "Practica 3 Biometria y Seguridad de Sistemas \n"
                + "Realizado por Daniel Correa \n"
                + "Cifrado y firma de clave pública");
    }//GEN-LAST:event_ayudaDanielActionPerformed

    private void opSalirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opSalirActionPerformed
        // TODO add your handling code here:
        this.dispose();
        System.exit(0);
    }//GEN-LAST:event_opSalirActionPerformed

    private void opClaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opClaveActionPerformed
        // TODO add your handling code here:
        Algoritmos alg = new Algoritmos(modelo);
        alg.setVisible(true);
        modelo = alg.getModelo();
    }//GEN-LAST:event_opClaveActionPerformed

    private void opGenerarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opGenerarActionPerformed
        try {
            // TODO add your handling code here:
            modelo.generarClaves();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
        }
        taLog.append("Claves generadas correctamente! \n");
    }//GEN-LAST:event_opGenerarActionPerformed

    private void opVeractualActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opVeractualActionPerformed
        // TODO add your handling code here:
        if(modelo.cargarArchivo()){
            taLog.append("Clave pública: "+modelo.getPublicKey()+"\n");
            taLog.append("Clave privada: "+modelo.getPrivateKey()+"\n");
        }else{
            taLog.append("No hay claves generadas, por favor genere una! \n");
        }
    }//GEN-LAST:event_opVeractualActionPerformed

    private void opCifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opCifrarActionPerformed
        // TODO add your handling code here:
        cargarArchivo();
        if(modelo.cargarArchivo()){
            try {
                modelo.cifrar(archivo);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else{
            taLog.append("No hay claves generadas, debe crearlas para poder operar");
        }
        
    }//GEN-LAST:event_opCifrarActionPerformed

    private void opDecifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opDecifrarActionPerformed
        // TODO add your handling code here:
        cargarArchivo();
        if(modelo.cargarArchivo()){
            try {
                modelo.decifrar(archivo);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else{
            taLog.append("No hay claves generadas, debe crearlas para poder operar");
        }
    }//GEN-LAST:event_opDecifrarActionPerformed

    private void opFirmarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opFirmarActionPerformed
        // TODO add your handling code here:
        cargarArchivo();
        if(modelo.cargarArchivo()){
            try {
                modelo.firmar(archivo);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else{
            taLog.append("No hay claves generadas, debe crearlas para poder operar");
        }
        
    }//GEN-LAST:event_opFirmarActionPerformed

    private void opVerificarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opVerificarActionPerformed
        // TODO add your handling code here:
        cargarArchivo();
        if(modelo.cargarArchivo()){
            try {
                if(modelo.verificarFirma(archivo)){
                    taLog.append("Firma verificada\n");
                }else{
                    taLog.append("Firma incorrecta\n");
                }
            } catch (IOException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                Logger.getLogger(Ventana.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else{
            taLog.append("No hay claves generadas, debe crearlas para poder operar");
        }
        
    }//GEN-LAST:event_opVerificarActionPerformed

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
            java.util.logging.Logger.getLogger(Ventana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Ventana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Ventana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Ventana.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Ventana().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenuItem ayudaDaniel;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu5;
    private javax.swing.JMenu jMenu6;
    private javax.swing.JMenuBar jMenuBar5;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JMenuItem opCifrar;
    private javax.swing.JMenuItem opClave;
    private javax.swing.JMenuItem opDecifrar;
    private javax.swing.JMenuItem opFirmar;
    private javax.swing.JMenuItem opGenerar;
    private javax.swing.JMenuItem opSalir;
    private javax.swing.JMenuItem opVeractual;
    private javax.swing.JMenuItem opVerificar;
    private javax.swing.JTextArea taLog;
    // End of variables declaration//GEN-END:variables
}
