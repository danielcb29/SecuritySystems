/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cifradopublica;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
/**
 *
 * @author daniel
 */
public class CifradoPublica {

    private String algoritmoCif = "RSA"; 
    private String algoritmoFir = "SHA1withRSA"; 
    private final String algoritmoClav = "RSA";
    private KeyPair claves;
    private Header cabecera;
    
    CifradoPublica(){
        
    }
    
    public boolean verificarFirma(File archivo) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        System.out.println("Proceso de verificación de firma de: "+archivo.getAbsolutePath());
        cabecera= new Header();
        FileInputStream fis = new FileInputStream(archivo.getAbsolutePath());
        if (cabecera.load(fis)){
          String alg = cabecera.getSigner();
          Signature dsa = Signature.getInstance(alg);
          dsa.initVerify(getPublicKey());
          byte[] sig = cabecera.getSign();
          
          byte[] data;
          //fis.read(data);
          
            byte[] buffer = new byte[8192];
            int bytesRead;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            while ((bytesRead = fis.read(buffer)) != -1)
            {
                output.write(buffer, 0, bytesRead);
            }
            data = output.toByteArray();
          
          
          dsa.update(data);
          boolean verifies = dsa.verify(sig);
          if (verifies){
              System.out.println("Firma Correcta!");
          }else{
              System.out.println("Firma incorrecta!");
          }
          return verifies;
        }
        else System.out.println("Error en la carga 2");
        fis.close();
        return false;
    }
    
    public void firmar(File archivo) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException{
        System.out.println("Proce de firma de: "+archivo.getAbsolutePath()+" con algoritmo: "+algoritmoFir);
        Signature dsa = Signature.getInstance(algoritmoFir);
        dsa.initSign(getPrivateKey());
        Path path = Paths.get(archivo.getAbsolutePath());
        byte[] data = Files.readAllBytes(path);
        dsa.update(data);
        byte[] sig = dsa.sign();
        cabecera = new Header(algoritmoFir,sig);
        FileOutputStream fos = new FileOutputStream(archivo.getAbsolutePath()+".sign");
        cabecera.save(fos);
        fos.write(data);
        fos.close();
        System.out.println("Firmado");
    
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
