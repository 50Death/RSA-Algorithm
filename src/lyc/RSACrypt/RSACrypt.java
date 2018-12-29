package lyc.RSACrypt;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Scanner;

/**
 * RSA加密算法
 *
 * @author lyc
 * @since 2018.12.19
 */

public class RSACrypt {
    /**
     * main函数
     * @param args
     */
    public static void main(String[] args) {
        try {
            //System.out.println("Usage: Input the fount number to select option\n1. I'm Alice\n2. I'm Bob\n0. I want to leave");
            while(true) {
                //init, generateKeyPair
                //公钥发送给消息发送方用于加密传输数据，私钥严格保存于消息接收方用于解密发来的加密信息

                HashMap<String, String> map = RSACrypt.getKeys();
                String privateKeyString = map.get("privateKey");
                String publicKeyString = map.get("publicKey");

                System.out.println("----------------------Sender---------------------------");
                String plainText = new String();
                Scanner scanner = new Scanner(System.in);
                plainText = scanner.nextLine();
                System.out.println("Private Key: " + privateKeyString);
                System.out.println("Public Key: " + publicKeyString);
                String cipherText = RSACrypt.encrypt(RSACrypt.loadPublicKey(publicKeyString), plainText.getBytes());
                System.out.println("Ciphered Text: " + cipherText);

                System.out.println("----------------------Receive--------------------------");
                String decipheredText = RSACrypt.deCrypt(RSACrypt.loadPrivateKey(privateKeyString), Base64.decodeBase64(cipherText));
                System.out.println("deCiphered Text: " + decipheredText);


                //init For Alice
                HashMap<String, String> map1 = RSACrypt.getKeys();
                String privateKeyStringForAlice = map1.get("privateKey");
                String publicKeyStringForAlice = map1.get("publicKey");

                //init For Bob
                HashMap<String,String> map2 = RSACrypt.getKeys();
                String privateKeyStringForBob = map2.get("privateKey");
                String publicKeyStringForBob = map2.get("publicKey");
                /*
                Scanner sc = new Scanner(System.in);
                int mode = sc.nextInt();
                sc.nextLine();
                if(mode == 1){
                    System.out.println("--------------------------------------------------------");
                    System.err.println("Alice's PrivateKey"+privateKeyStringForAlice);
                    System.out.println("Bob's PublicKey"+publicKeyStringForBob);
                    String text = sc.nextLine();
                    String cipherText =
                }*/
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成RSA公钥私钥字符串并返回
     * HashMap详解见https://www.cnblogs.com/skywang12345/p/3310835.html
     *
     * @return
     */
    public static HashMap<String, String> getKeys() {
        HashMap<String, String> map = new HashMap<String, String>();
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //初始化密钥对生成器，秘钥大小96-1024bit
        keyPairGenerator.initialize(1024, new SecureRandom());
        //生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //得到公钥字符串
        String publicKey = Base64.encodeBase64String(keyPair.getPublic().getEncoded());
        String privateKey = Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
        map.put("publicKey", publicKey);
        map.put("privateKey", privateKey);
        return map;
    }

    /**
     * 根据公钥字符串加载公钥
     *
     * @param publicKeyString 公钥字符串
     * @return
     * @throws Exception
     */
    public static RSAPublicKey loadPublicKey(String publicKeyString) throws Exception {
        try {
            byte[] buffer = javax.xml.bind.DatatypeConverter.parseBase64Binary(publicKeyString);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No Such Algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw new Exception("Illegal PublicKey", e);
        } catch (NullPointerException e) {
            throw new Exception("PublicKey's Data is Empty", e);
        }
    }

    /**
     * 根据私钥字符串加载私钥
     *
     * @param privateKeyString 私钥字符串
     * @return
     * @throws Exception
     */
    public static RSAPrivateKey loadPrivateKey(String privateKeyString) throws Exception {
        try {
            byte[] buffer = javax.xml.bind.DatatypeConverter.parseBase64Binary(privateKeyString);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No Such Algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw new Exception("Illegal PrivateKey", e);
        } catch (NullPointerException e) {
            throw new Exception("PrivateKey's Data is Empty", e);
        }
    }

    /**
     * 公钥加密
     *
     * @param publicKey 公钥
     * @param plainText 明文数据
     * @return
     * @throws Exception 异常
     */
    public static String encrypt(RSAPublicKey publicKey, byte[] plainText) throws Exception {
        if (publicKey == null) {
            throw new Exception("Please Set PublicKey!");
        }
        Cipher cipher = null;
        try {
            //使用默认RSA
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] output = cipher.doFinal(plainText);
            return Base64.encodeBase64String(output);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No Such enCrypt Algorithm", e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("Illegal PublicKey, Please Check!");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("Illegal length of PlainText!");
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new Exception("PlainText is Broken!");
        }
    }

    public static String deCrypt(RSAPrivateKey privateKey, byte[] cipherText) throws Exception {
        if (privateKey == null) {
            throw new Exception("deCrypt PrivateKey unSet!Please Check!");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] output = cipher.doFinal(cipherText);
            return new String(output);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("No Such deCrypt Algorithm!");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("deCrypt PrivateKey Illegal, Please Check!");
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new Exception("Illegal length of CipherText");
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new Exception("CipherText is Broken");
        }
    }
}
