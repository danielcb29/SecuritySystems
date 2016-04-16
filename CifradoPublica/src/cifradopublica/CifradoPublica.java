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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
    private final int blockCifSize = 53;
    private final int blockDcifSize = 64;
    
    CifradoPublica(){
        
    }
    
    public void decifrar(File archivo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, IOException, IllegalBlockSizeException, BadPaddingException{
        
        FileInputStream fis = new FileInputStream(archivo.getAbsolutePath());
        cabecera = new Header();
        if (cabecera.load(fis)){
            String alg = cabecera.getCipher();
            System.out.println("Proceso de decifrado de: "+archivo.getAbsolutePath()+" con algoritmo: "+alg);
            Cipher c = Cipher.getInstance(alg);
            c.init(c.DECRYPT_MODE,getPrivateKey());
            FileOutputStream fos = new FileOutputStream(archivo.getAbsolutePath()+".dclear");
            byte[] b = new byte[blockDcifSize];
            //Empezamos a leer
            int i = fis.read(b);
            while (i >= 0) {
                System.out.print(i+".");
                byte out[] = c.doFinal(b);
                fos.write(out);
                i = fis.read(b);
            }
            fos.close();
            System.out.println("");
            System.out.println("Hecho.");

        }
        else System.out.println("Error en la carga de cabecera de cifrado");
        fis.close();
        
        
        

    }
    
    public void cifrar(File archivo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, IllegalBlockSizeException, BadPaddingException, IOException{
        System.out.println("Proceso de cifrado de: "+archivo.getAbsolutePath()+" con algoritmo: "+algoritmoCif);
        Cipher c = Cipher.getInstance(algoritmoCif);
        c.init(c.ENCRYPT_MODE,getPublicKey());
        FileOutputStream fos = new FileOutputStream(archivo.getAbsolutePath()+".dcif");
        cabecera = new Header(algoritmoCif);
        cabecera.save(fos);
        FileInputStream fis = new FileInputStream(archivo.getAbsolutePath());
        byte[] b = new byte[blockCifSize];
        int i = fis.read(b);
        while (i != -1) {
            System.out.print(i+".");
            byte out[] = c.doFinal(b);
            fos.write(out);
            i = fis.read(b);
        }
        fos.close();
        fis.close();
        System.out.println("");
        System.out.println("Hecho.");
        
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
              FileOutputStream fos = new FileOutputStream(archivo.getAbsolutePath()+".clear");
              fos.write(data);
              fos.close();
          }else{
              System.out.println("Firma incorrecta!");
          }
          return verifies;
        }
        else System.out.println("Error en la carga de cabecera de firma");
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
