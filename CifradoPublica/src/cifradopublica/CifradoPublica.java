/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cifradopublica;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author daniel
 */
public class CifradoPublica {

    private String algoritmoCif = "RSA"; 
    private String algoritmoFir = "SHA1withRSA"; 
    private final String algoritmoClav = "RSA";
    private KeyPair claves;
    
    CifradoPublica(){
        
    }
    
    
    public PublicKey getPublicKey(){
        return claves.getPublic();
    }
    
    public PrivateKey getPrivateKey(){
        return claves.getPrivate();
    }
    
    public void generarClaves() throws NoSuchAlgorithmException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algoritmoClav);
        kpg.initialize(512); // 512 bits
        
        claves = kpg.generateKeyPair();
        guardarArchivo();
    }
    
    
    public void setAlgoritmoCif(String alg){
        algoritmoCif=alg;
    }
    
    public void setAlgoritmoFir(String alg){
        algoritmoFir=alg;
    }
    
    public boolean cargarArchivo(){
        try {
                FileInputStream fis = new FileInputStream("claves.key");
                ObjectInputStream ois = new ObjectInputStream(fis);
                this.claves = (KeyPair) ois.readObject();
                return true;
        }
        catch (Exception e) { 
                return false; 
        }
    }
    
    public void guardarArchivo(){
        try {
            FileOutputStream fos = new FileOutputStream("claves.key");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(this.claves);
        }
        catch (Exception e) { System.out.println(e); }
    }
    
    
}
