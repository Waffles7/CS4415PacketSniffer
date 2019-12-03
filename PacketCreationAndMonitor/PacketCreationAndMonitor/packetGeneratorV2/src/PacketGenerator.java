package PacketCreationAndMonitor.packetGeneratorV2.src;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

public class PacketGenerator {
    public static void main(String[] args) {
        try {
            /*String[] commands = {"../elevateRawCap.bat"};
            ProcessBuilder pb = new ProcessBuilder(commands);
            Process curProcess = pb.start();

            System.out.println("Please allow admin access, so we can capture packets on the localhost.\n");
            System.out.println("Press any key to continue");
            Scanner scanner = new Scanner(System.in);
            scanner.next();*/

            for (int i = 0; i < 10; i++) {
                HttpsURLConnection conn = (HttpsURLConnection) new URL("https://192.168.2.43").openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");

                InputStream in = new BufferedInputStream(conn.getInputStream());
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
                //Thread.sleep(10000000);
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
    }
}
