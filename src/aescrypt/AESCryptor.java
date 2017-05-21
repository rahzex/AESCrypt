/*
* MIT License
*
* Copyright (c) 2017 rahzex:Rahul Pal
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
 */
package aescrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Rahul Pal
 */
public class AESCryptor {
    
    private static byte[] salt;
    private static final int pswdIterations = 65536  ;
    private static final int keySize = 256;
    private static byte[] ivBytes;
    private static byte[] saltIV;

    static{
        saltIV = new byte[48];
        salt = new byte[32];
        ivBytes =new byte[16];
    }
     
    protected static void encryptFile(String plainFile,String encryptedFile,char[] password,boolean deleteOriginalFile) throws IOException {   
        
            String plainFilePath = plainFile;
            String encryptedFilePath = encryptedFile;
            
            File f = new File(plainFile);
            String fileName = f.getName();
            
        //generate salt ,iv & save them
            salt = generateSalt();
            ivBytes = generateIV();
        
            System.arraycopy(salt, 0, saltIV, 0, salt.length);
            System.arraycopy(ivBytes, 0, saltIV, salt.length, ivBytes.length);
        
            FileOutputStream saltIvOutFile = new FileOutputStream( encryptedFilePath + File.separator +fileName +".ats");
            saltIvOutFile.write(saltIV);
            saltIvOutFile.close();
        
        // file to be encrypted
            FileInputStream inFile = new FileInputStream(plainFilePath);

	// encrypted file
            FileOutputStream outFile = new FileOutputStream(encryptedFilePath + File.separator + fileName);
         
        // Derive the key
        SecretKeyFactory factory = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        PBEKeySpec spec = new PBEKeySpec(
                password, 
                salt, 
                pswdIterations, 
                keySize
                );
 
        SecretKey secretKey = null;
        try {
            secretKey = factory.generateSecret(spec);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        //initializing Cipher
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secret,new IvParameterSpec(ivBytes));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //file encryption
                byte[] input = new byte[64];
		int bytesRead;

		while ((bytesRead = inFile.read(input)) != -1) {
			byte[] output = cipher.update(input, 0, bytesRead);
			if (output != null)
				outFile.write(output);
		}

		byte[] output = null;
                try {
                    output = cipher.doFinal();
                } catch (IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
                }
                
		if (output != null)
			outFile.write(output);

                
		inFile.close();
		outFile.flush();
		outFile.close();
                resetValues(cipher);
                
                //delete original file
                if(deleteOriginalFile)
                    f.delete();

		System.out.println("File Encrypted.");
        
    }
    
   protected static void decryptFile(String outFile,String inFile,char[] password) throws IOException {
        
        String filePath = inFile;
        String decryptedFilePath = outFile;
        
        File f = new File(inFile);
        String fileName = f.getName();
        
	// reading the salt and iv
	FileInputStream saltIvInFile = new FileInputStream( filePath + ".ats");
	saltIvInFile.read(saltIV);
        saltIvInFile.close();
        
	System.arraycopy(saltIV, 0, salt, 0, salt.length);
        System.arraycopy(saltIV, salt.length, ivBytes, 0, ivBytes.length);
 
        // Derive the key
        SecretKeyFactory factory = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        PBEKeySpec spec = new PBEKeySpec(
                password, 
                salt, 
                pswdIterations, 
                keySize
                );
 
        SecretKey secretKey = null;
        try {
            secretKey = factory.generateSecret(spec);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        // file decryption
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
     
         FileInputStream fis = new FileInputStream(filePath);
	 FileOutputStream fos = new FileOutputStream(decryptedFilePath + File.separator + fileName);
		byte[] in = new byte[64];
		int read;
		while ((read = fis.read(in)) != -1) {
			byte[] output = cipher.update(in, 0, read);
			if (output != null)
				fos.write(output);
		}

		byte[] output = null;
                try {
                    output = cipher.doFinal();
                } catch (IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(AESCryptor.class.getName()).log(Level.SEVERE, null, ex);
                }
                
		if (output != null)
			fos.write(output);
                
		fis.close();
		fos.flush();
		fos.close();
                resetValues(cipher);
		System.out.println("File Decrypted.");
    }
    
 
    public static byte[] generateSalt() throws IOException {
        byte[] saltValue = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
	secureRandom.nextBytes(saltValue);
        return saltValue;
    }
    
     public static byte[] generateIV() throws IOException {
        byte[] ivValue = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
	secureRandom.nextBytes(ivValue);
        return ivValue;
    }
    
    public static void resetValues(Cipher cipher)
    {
        cipher = null;
    }
}
