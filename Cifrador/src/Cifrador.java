import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class Cifrador {
	
	public static Cipher getCifrador(char[] f1,Header cabecera){
		PBEKeySpec pbeKeySpec = new PBEKeySpec(f1);
		PBEParameterSpec pPS = new PBEParameterSpec(cabecera.getSalt(),20);
		Cipher c = null;
		try { 
			SecretKeyFactory kf = SecretKeyFactory.getInstance(cabecera.getAlgorithm());
			SecretKey sKey= kf.generateSecret(pbeKeySpec);
			c = Cipher.getInstance(cabecera.getAlgorithm());
			c.init(Cipher.ENCRYPT_MODE,sKey,pPS);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("El algormito elegido no funciona con esta aplicacion");
			System.out.println("Lista de algoritmos: PBEWithMD5AndDES, PBEWithMD5AndTripleDES1,PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40");
			System.exit(0);
		}catch (InvalidKeySpecException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			System.exit(0);
		}
		
		return c;
	}
	
	public static void decifrar(InputStream archivo,Header cabecera,String path) throws IOException{
		Console console = System.console();

        char[] f1 = console.readPassword("[Frase de paso:]");
        Cipher c = getCifrador(f1, cabecera);
        
        CipherInputStream cis = new CipherInputStream(archivo,c);
        
        OutputStream fos = new FileOutputStream(path+".dcla");
        byte[] b = new byte[512];
        int i = cis.read(b);
        int total = i;
        while (i != -1) {
        	System.out.print(i+".");
            fos.write(b, 0, i);
            i = cis.read(b);
            total+=i;
        }
        fos.close();
        cis.close();
        System.out.println("");
        System.out.println("Hecho:"+total);

	}
	
	public static void cifrar(FileInputStream archivo,Header cabecera,String path) throws IOException{
		
		Console console = System.console();

        char[] f1 = console.readPassword("[Frase de paso:]");
        char[] f2 = console.readPassword("[Repetir frase de paso:]");
        
        if(!(new String(f1)).equals(new String(f2))){
        	System.out.println("Las frases de paso deben ser iguales");
        	System.exit(0);
        }
        
        Cipher c = getCifrador(f1, cabecera);
		
        FileOutputStream out = new FileOutputStream(path+".dcif");
        
		CipherOutputStream cos = new CipherOutputStream(out,c);
		cabecera.save(out);
		//archivo.reset();
		System.out.println(archivo.available());
		byte[] b = new byte[1024];
	    int i = archivo.read(b);
	    int total = i;
	    while (i != -1) {
	    	System.out.print(i+".");
	    	//cos.write(b);
	        cos.write(b, 0, i);
	        i = archivo.read(b);
	        total+=i;
	    }
	    cos.flush();
		out.close();
		cos.close();
		System.out.println("");
		System.out.println("Hecho:"+total);
		
	}
	
	public static void main(String args[]) throws IOException{
		//Se valida que ingresen los argumentos
		if(args.length == 0){
			System.out.println("Debe ingresar por paramatero como minimo la dirección del archivo, el algortimo es opcional");
			System.exit(0);
		}
		String path = args[0];
		Header cabecera = new Header();
		//Si se ingreso un parametro algoritmo de asigna 
		if(args.length > 1){
			cabecera.setAlgorithm(args[1]);
		}
		
		//Se intenta cargar el archivo
		FileInputStream in = null;
		try {
			in = new FileInputStream(new File(path));
		} catch (FileNotFoundException e) {
			System.out.println("Ingrese una direccion de archivo valida");
			System.exit(0);
		}
		
		System.out.println("Practica 2 BySS Daniel Correa");
		String ex="";
		if(!cabecera.load(in)){
			System.out.println("Vamos a cifrar!:");
			System.out.println("Algoritmo: "+cabecera.getAlgorithm());
			cifrar(in,cabecera,path);
			ex = ".dcif";
		}else{
			System.out.println("Vamos a decifrar!:");
			System.out.println("Algoritmo: "+cabecera.getAlgorithm());
			decifrar(in,cabecera,path);
			ex = ".dclear";
		}
		System.out.println("Proceso terminado");
		System.out.println("Nuevo archivo: "+path+ex);
		
	}
}
