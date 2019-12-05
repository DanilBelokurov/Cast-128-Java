import java.util.ArrayList;
import java.util.Scanner;

class Main {
    public static void main(String[] args) throws Exception {

        /* IO io = new IO();
        ArrayList<byte[]> message = io.read("pic.jpg");

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your key: ");
        byte[] key = scanner.nextLine().getBytes(); */

        byte[] key = { 0x01, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, (byte) 0x89, 0x34, 0x56, 0x78,
               (byte) 0x9A};

        byte[] message = { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
        System.out.print("Text -> ");
        for (int j = 0; j < message.length; j++) {
                System.out.print(Integer.toHexString(message[j] & 0xFF) + " ");
        }
        System.out.println();

        try {
            Cast cast = new Cast(key, message);
            cast.makeKey();
            cast.encrypt();
            //io.write("pic_crypto.jpg", cast.getCryptoTextList());
            //io.write("cryptotext.txt", cast.getCryptoTextList());
            cast.printCryptotext();
            cast.decrypt();
            //io.write("pic_plain.jpg", cast.getDecryptoTextList());
            //io.write("plaintext.txt", cast.getDecryptoTextList());
            cast.printPlaintext();
        } catch (Exception e) {
            e.printStackTrace();
         }

    }
}