/**
 * CS255 project 2
 */
package mitm;

import java.io.*;
import java.net.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64Encoder;

public class MITMAdminClient
{
    private Socket m_remoteSocket;
    private String password;
    private String command;
    private String commonName = "";
    
    public static void main( String [] args ) {
        MITMAdminClient admin = new MITMAdminClient( args );
        admin.run();
    }

     private Error printUsage() {
        System.err.println(
            "\n" +
            "Usage: " +
            "\n java " + MITMAdminClient.class + " <options>" +
            "\n" +
            "\n Where options can include:" +
            "\n" +
            "\n   <-password <pass> >   " +
            "\n   <-cmd <shudown|stats>" +
            "\n   [-remoteHost <host name/ip>]  Default is localhost" +
            "\n   [-remotePort <port>]          Default is 8002" +
            "\n"
            );

        System.exit(1);
        return null;
    }


    private static class TrustEveryone implements javax.net.ssl.X509TrustManager
    {
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
                                       String authenticationType) {
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
                                       String authenticationType) {
        }

        public java.security.cert.X509Certificate[] getAcceptedIssuers()
        {
            return null;
        }
    }


    private MITMAdminClient( String [] args ) {
        int remotePort = 8002;
        String remoteHost = "localhost";
                
        if( args.length < 3 )
            throw printUsage();
        
        try {
            for (int i=0; i<args.length; i++)
            {
                if (args[i].equals("-remoteHost")) {
                    remoteHost = args[++i];
                } else if (args[i].equals("-remotePort")) {
                    remotePort = Integer.parseInt(args[++i]);
                } else if (args[i].equals("-password")) {
                    password = args[++i];
                } else if (args[i].equals("-cmd")) {
                    command = args[++i];
                    if( command.equals("enable") || command.equals("disable") ) {
                        commonName = args[++i];
                    }
                } else {
                    throw printUsage();
                }
            }

            SSLContext sslContext = SSLContext.getInstance( "SSL" );

            sslContext.init(
                new javax.net.ssl.KeyManager[] {}
                , new TrustManager[] { new TrustEveryone() }
                , null
                );

            m_remoteSocket = (SSLSocket) sslContext.getSocketFactory().createSocket( remoteHost, remotePort );
        }
        catch (Exception e) {
            throw printUsage();
        }

    }

    public static String generateResponse(String challenge, String password) throws GeneralSecurityException {
        byte[] hmacData = null;
 
        try {
            SecretKeySpec secretKey = new SecretKeySpec(password.getBytes("UTF-8"), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            hmacData = mac.doFinal(challenge.getBytes("UTF-8"));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Base64Encoder().encode(hmacData, 0, hmacData.length, baos);
            return baos.toString();
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }
    
    public void run() 
    {
        try {
            if( m_remoteSocket != null ) {
 
		BufferedInputStream in =
                    new BufferedInputStream(m_socket.getInputStream(),
                                            buffer.length);
		
		int bytesRead = in.read(buffer);

                String challenge =
                    bytesRead > 0 ?
                    new String(buffer, 0, bytesRead) : "";

		String response = generateResponse(challenge, password);

		PrintWriter writer =
                    new PrintWriter( m_remoteSocket.getOutputStream() );
                writer.println("response:"+response);
                writer.println("command:"+command);
                writer.println("CN:"+commonName);
                writer.flush();
            }

            // now read back any response

            System.out.println("");
            System.out.println("Receiving input from MITM proxy:");
            System.out.println("");
            BufferedReader r = new BufferedReader(new InputStreamReader(m_remoteSocket.getInputStream()));
            String line = null;
            while ((line = r.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.err.println("Admin Client exited");
        System.exit(0);
    }
}
