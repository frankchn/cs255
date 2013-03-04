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

class MITMAdminServer implements Runnable
{
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    
    public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException,GeneralSecurityException {
        MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
                                
        m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
        m_engine = engine;
    }

    // adapted from http://stackoverflow.com/questions/923863/converting-a-string-to-hexadecimal-in-java
    public static String toHexString(byte[] ba) {
        StringBuilder str = new StringBuilder();
        for(int i = 0; i < ba.length; i++)
            str.append(String.format("%02x", ba[i]));
        return str.toString();
    }

    public static byte[] fromHexString(String hex) {
        byte[] rtn = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i+=2) {
            rtn[i / 2] = ((byte) Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        return rtn;
    }

    // adapted from http://stackoverflow.com/questions/2860943/suggestions-for-library-to-hash-passwords-in-java
    public static String hash(String password, byte[] salt) throws Exception {
        if(password == null || password.length() == 0)
            throw new IllegalArgumentException("Empty passwords are not supported.");
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = f.generateSecret(new PBEKeySpec(
            password.toCharArray(), salt, 10000, 256)
        );
        return toHexString(key.getEncoded());
    }

    public static String getSaltedHash(String password) {
        try {
            byte[] salt = SecureRandom.getInstance("SHA1PRNG").generateSeed(32);
            return toHexString(salt) + "$" + hash(password, salt);
        } catch (Exception e) {
            throw new RuntimeException("Cryptography subsystem cannot be initialized");
        }
    }

    public static boolean check(String password, String stored) {
        try {
            String[] sp = stored.split("\\$");
            if(sp.length != 2) return false;
            String hoi = hash(password, fromHexString(sp[0]));
            return hoi.equals(sp[1]);
        } catch (Exception e) {
            throw new RuntimeException("Cryptography subsystem cannot be initialized");
        }
    }

    public void run() {
        //System.out.println("Pwd = " + getSaltedHash("cs255test"));

        System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
        while( true ) {
            try {
                m_socket = m_serverSocket.accept();

                byte[] buffer = new byte[40960];

                Pattern userPwdPattern =
                    Pattern.compile("password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
                
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
                    String password = userPwdMatcher.group(1);

                    boolean authenticated = false;

                    for(String sp : MITMProxyServer.passwords) {
                        if(check(password, sp))
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
            sendString("Sockets opened: " + MITMSSLSocketFactory.socketinit);
        } else {
            sendString("Unknown command: " + cmd);
        }

        m_socket.close();
        
    }

}
