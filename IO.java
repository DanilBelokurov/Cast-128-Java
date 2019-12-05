import java.io.*;
import java.util.ArrayList;


public class IO {

    private int blockSize = 8;
    private byte[] buffer;
    private ArrayList<byte[]> plaintext = new ArrayList<>();
    private int additionBits = 0;
    private int fullBlocks = 0;

    public ArrayList<byte[]> read(String filename) throws Exception {

        if (filename.equals(""))
            throw new Exception("File " + filename + " not found");

        FileInputStream fin = new FileInputStream(filename);
        buffer = new byte[fin.available()];
        fin.read(buffer, 0, fin.available());
        fin.close();

        fullBlocks = buffer.length / blockSize;
        additionBits = buffer.length % blockSize;

        byte[] tmp = new byte[8];
        for (int i = 0; i < fullBlocks; i++) {
            tmp = new byte[8];
            for (int j = 0; j < blockSize; j++)
                tmp[j] = buffer[j + i * blockSize];
            plaintext.add(i, tmp);
        }

        if (buffer.length % blockSize != 0) {
            tmp = new byte[8];
            for (int i = blockSize * fullBlocks; i < buffer.length; i++)
                tmp[i % blockSize] = buffer[i];

            for (int i = buffer.length % blockSize; i < tmp.length; i++) {
                tmp[i] = 0;
            }
            plaintext.add(tmp);
        }

        return plaintext;
    }

    public void write(String filename, ArrayList<byte[]> data) {

        File file = new File(filename);
        try {

            if (!file.exists()) {
                file.createNewFile();
            }

            if (!filename.contains(".txt")) {

                byte[] image = new byte[blockSize * data.size() - additionBits];

                int counter = 0;
                for (int i = 0; i < data.size(); i++) {
                    for (int j = 0; j < blockSize; j++) {

                        if (counter == blockSize * data.size() - additionBits)
                            break;
                        
                        image[counter] = data.get(i)[j];
                        counter++;
                    }
                }

                FileOutputStream stream = new FileOutputStream(file);
                stream.write(image);
                stream.close();


            } else {
                PrintWriter out = new PrintWriter(file.getAbsoluteFile());
                try {
                    for (int i = 0; i < data.size(); i++) {
                        for (int j = 0; j < data.get(i).length; j++) {
                            if (i == data.size() - 1 & j == additionBits)
                                break;
                            out.print((char) (data.get(i)[j] & 0xFF));
                        }
                    }
                } finally {
                    out.close();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}