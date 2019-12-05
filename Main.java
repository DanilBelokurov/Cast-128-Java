
class Main {
    public static void main(String[] args) {

        byte[] key = { 0x01, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, (byte) 0x89, 0x34, 0x56, 0x78,
                (byte) 0x9A};
        byte[] message = { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };

        for (int i = 0; i < message.length; i++) {
            System.out.print(Integer.toHexString(message[i] & 0xFF) + " ");
        }
        System.out.println();

        try {
            Cast cast = new Cast(key, message);
            cast.makeKey();
            cast.encrypt();
            cast.printResult();
            cast.decrypt();
            cast.printResult1();
        } catch (Exception e) { }

    }

}