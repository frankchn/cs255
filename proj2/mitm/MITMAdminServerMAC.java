/**
 * CS255 project 2
 */

package mitm;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.regex.*;
import javax.crypto.Mac;
import javax.crypto.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64Encoder;
import java.security.SecureRandom;
import java.math.BigInteger;

class MITMAdminServerMAC implements Runnable
{
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    private SecureRandom random = new SecureRandom();
    
    public MITMAdminServerMAC( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException,GeneralSecurityException {
        MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
                                
        m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
        m_engine = engine;
    }

    public static String generateResponse(String challenge, String password) throws GeneralSecurityException {
        byte[] hmacData = null;
 
        try {
            SecretKeySpec secretKey = new SecretKeySpec(password.getBytes("UTF-8"), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            hmacData = mac.doFinal(challenge.getBytes("UTF-8"));
            return new Base64Encoder().encode(hmacData);
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }


    public void run() {

        System.out.println("MAC Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
        while( true ) {
            try {
                m_socket = m_serverSocket.accept();

                byte[] buffer = new byte[40960];

		string challenge = 
		    new BigInteger(130, random).toString(32);

		PrintWriter writer = 
		    new PrintWriter( m_socket.getOutputStream() );

		writer.println(challenge);
		writer.flush();

                Pattern userPwdPattern =
                    Pattern.compile("response:(\\S+)\\s+command:(\\S+)\\s+CN:(\\S*)\\s");
                
                BufferedInputStream in =
                    new BufferedInputStream(m_socket.getInputStream(),
                                            buffer.length);

                // Read a buffer full.
                int bytesRead = in.read(buffer);

                String line =
                    bytesRead > 0 ?
                    new String(buffer, 0, bytesRead) : "";

                Matcher userPwdMatcher =
                    userPwdPattern.matcher(line);

                // parse username and pwd
                if (userPwdMatcher.find()) {
                    String clientResponse = userPwdMatcher.group(1);

                    boolean authenticated = false;

                    for(String sp : MITMProxyServer.passwords) {
			String response = generateResponse(challenge,
							   password);
                        if( clientResponse == response )
                            authenticated = true;
                    }

                    // if authenticated, do the command
                    if( authenticated ) {
                        String command = userPwdMatcher.group(2);
                        String commonName = userPwdMatcher.group(3);

                        doCommand( command );
                    } else {
                        sendString("Wrong password!");
                        m_socket.close();
                    }
                } else {
                    System.out.println("Cannot find password string for some reason.");
                }      
            }
            catch( InterruptedIOException e ) {
            }
            catch( Exception e ) {
                e.printStackTrace();
            }
        }
    }

    private void sendString(final String str) throws IOException {
        PrintWriter writer = new PrintWriter( m_socket.getOutputStream() );
        writer.println(str);
        writer.flush();
    }
    
    private void doCommand( String cmd ) throws IOException {

        // TODO(cs255): instead of greeting admin client, run the indicated command

        if(cmd.equals("shutdown")) {
            sendString("Exiting proxy...");
            System.exit(0);
        } else if(cmd.equals("stats")) {
            sendString("CONNECTs received: " + HTTPSProxyEngine.CONNECTCount);
        } else {
            sendString("Unknown command: " + cmd);
        }

        m_socket.close();
        
    }

}
