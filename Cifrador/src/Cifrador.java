import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
/**
 * Practica 2 Biometria y Seguridad de Sistemas
 * @author Daniel Correa Barrios
 *
 */
public class Cifrador {
	/**
	 * Permite obtener un cifrador a partir de una clave f1, una cabecera y un modo de operacion [true para encriptar, false para desencriptar]
	 * @param f1: Clave de usuario
	 * @param cabecera: Cabecera
	 * @param modo: Modo de operacion
	 * @return: Cifrador inicializado
	 */
	public static Cipher getCifrador(char[] f1,Header cabecera,boolean modo){
		PBEKeySpec pbeKeySpec = new PBEKeySpec(f1);
		PBEParameterSpec pPS = new PBEParameterSpec(cabecera.getSalt(),20);
		Cipher c = null;
		try { 
			SecretKeyFactory kf = SecretKeyFactory.getInstance(cabecera.getAlgorithm());
			SecretKey sKey= kf.generateSecret(pbeKeySpec);
			c = Cipher.getInstance(cabecera.getAlgorithm());
			if(modo){
				c.init(Cipher.ENCRYPT_MODE,sKey,pPS);
			}else{
				c.init(Cipher.DECRYPT_MODE,sKey,pPS);
			}
			
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
	/**
	 * Permite decifrar el contendo de un archivo dada su cabecera y su ruta.
	 * @param archivo: InputStream a decifrar sin cabecera
	 * @param cabecera: Objeto cabecera
	 * @param path: Direccion donde se localiza el archivo
	 * @throws IOException
	 */
	public static void decifrar(InputStream archivo,Header cabecera,String path) throws IOException{
		Console console = System.console();
		//Obtenemos la frase de paso
        char[] f1 = console.readPassword("[Frase de paso:]");
        //Obtenemos los parametros necesarios
        Cipher c = getCifrador(f1, cabecera,false);
        CipherInputStream cis = new CipherInputStream(archivo,c);
        OutputStream fos = new FileOutputStream(path+".dcla");
        byte[] b = new byte[1024];
        //Empezamos a leer
        int i = cis.read(b);
        int total = i+1;
        //Leemos hasta vaciar el buffer
        while (i >= 0) {
        	System.out.print(i+".");
            fos.write(b, 0, i);
            i = cis.read(b);
            total+=i;
        }
        //Cerramos todos los streams utilizados
        fos.flush();
        fos.close();
        cis.close();
        archivo.close();
        System.out.println("");
        System.out.println("Hecho:"+total);

	}
	/**
	 * Permite cifrar el contenido de un archivo dada su cabecera y ubicacion
	 * @param archivo: InputStream a cifrar
	 * @param cabecera: Objeto cabecera
	 * @param path: Direccion donde se localiza el archivo
	 * @throws IOException
	 */
	public static void cifrar(InputStream archivo,Header cabecera,String path) throws IOException{
		
		Console console = System.console();
		//Obtenemos las frases de paso
        char[] f1 = console.readPassword("[Frase de paso:]");
        char[] f2 = console.readPassword("[Repetir frase de paso:]");
        //Comprobamos que sean iguales
        if(!(new String(f1)).equals(new String(f2))){
        	System.out.println("Las frases de paso deben ser iguales");
        	System.exit(0);
        }
        //Obtenemos los paramteros necesarios
        Cipher c = getCifrador(f1, cabecera,true);
        OutputStream out = new FileOutputStream(path+".dcif");
        cabecera.save(out); //Escribimos la cabecera en el OutputStream
        CipherOutputStream cos = new CipherOutputStream(out,c);
		byte[] b = new byte[512];
		//Empezamos a leer el archivo
	    int i = archivo.read(b);
	    int total = i+1;
	    //Leemos hasta vaciar el buffer
	    while (i != -1) {
	    	System.out.print(i+".");
	    	cos.write(b, 0, i);
	        i = archivo.read(b);
	        total+=i;
	    }
	    //Cerramos todos los streams utilizados
	    cos.flush();
		cos.close();
		out.close();
		archivo.close();
		System.out.println("");
		System.out.println("Hecho:"+total);
		
	}
	/**
	 * A partir de una ruta y un algoritmo (opcional) se cifra o decifra el contenido del archivo que se encuentra en la ruta
	 * @param args: Ruta del archivo y algoritmo de cifrado (opcional)
	 * @throws IOException 
	 */
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
		InputStream in = null;
		InputStream in_dcif = null;
		//Se traen dos copias del archivo para procesarlas
		try {
			in =  new FileInputStream(new File(path));
			in_dcif =new FileInputStream(new File(path));
		} catch (FileNotFoundException e) {
			System.out.println("Ingrese una direccion de archivo valida");
			System.exit(0);
		}
		
		System.out.println("Practica 2 BySS Daniel Correa");
		String ex="";
		if(!cabecera.load(in_dcif)){
			//En caso de que no se pueda cargar la cabecera se cifra el contenido de archivo
			System.out.println("Vamos a cifrar!:");
			System.out.println("Algoritmo: "+cabecera.getAlgorithm());
			cifrar(in,cabecera,path);
			ex = ".dcif";
		}else{
			//En caso contrario se decifra el contenido del archivo
			System.out.println("Vamos a decifrar!:");
			System.out.println("Algoritmo: "+cabecera.getAlgorithm());
			decifrar(in_dcif ,cabecera,path);
			ex = ".dclear";
		}
		System.out.println("Proceso terminado");
		System.out.println("Nuevo archivo: "+path+ex);
		
	}
}
