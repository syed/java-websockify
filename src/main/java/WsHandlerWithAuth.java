import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketFrame;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;
import org.eclipse.jetty.websocket.api.extensions.Frame;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.spec.KeySpec;

// http://jansipke.nl/websocket-tutorial-with-java-server-jetty-and-javascript-client/

@WebSocket
public class WsHandlerWithAuth extends WebSocketHandler {

    private Session session;

    private static enum VncState {
        SERVER_VERSION_SENT, AUTH_TYPES_SENT, AUTH_RESULT_SENT, UNKNOWN
    }
    public final static int CONNECTION_FAILED = 0, NO_AUTH = 1, VNC_AUTH = 2;
    public final static int VNC_AUTH_OK = 0, VNC_AUTH_FAILED = 1, VNC_AUTH_TOO_MANY = 2;
    public static final Charset CHARSET = Charset.availableCharsets().get("US-ASCII");

    // protocol messages
    private static final String M_VNC_VERSION = "RFB 003.008\n";
    private static final byte[] M_VNC_AUTH_OK = new byte[]{0, 0, 0, 0};
    private static final byte[] M_VNC_AUTH_TYE_NOAUTH = new byte[]{01, 01};

    Socket vncSocket;
    int vncPort = 5900;
    String vncPassword = "password";

    VncState clientState;


    @Override
    public void configure(WebSocketServletFactory webSocketServletFactory) {
        webSocketServletFactory.register(WsHandlerWithAuth.class);
    }

    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if(this.getWebSocketFactory().isUpgradeRequest(request, response)) {
            response.addHeader("Sec-WebSocket-Protocol", "binary");
            if(this.getWebSocketFactory().acceptWebSocket(request, response)) {
                baseRequest.setHandled(true);
                return;
            }

            if(response.isCommitted()) {
                return;
            }
        }

        super.handle(target, baseRequest, request, response);
    }

    @OnWebSocketConnect
    public void onConnect(final Session session) throws IOException, InterruptedException {
        System.out.println("Connect (With AUTH): " + session.getRemoteAddress().getAddress());
        System.out.println(session.getUpgradeRequest().getRequestURI());

        // first, connect to the server
        vncSocket = new Socket("127.0.0.1", vncPort);
        this.session = session;
        initServer(vncSocket);
        initClient(session);

        Thread readThread =  new Thread(new Runnable() {
            public void run() {
                try {
                    byte[] b = new byte[1500];
                    int readBytes;
                    while (true){
                        readBytes = vncSocket.getInputStream().read(b);
                        System.out.printf("read bytes %d\n", readBytes);
                        if (readBytes == -1){
                            break;
                        }
                        if (readBytes > 0) {
                            session.getRemote().sendBytes(ByteBuffer.wrap(b,0, readBytes));
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        readThread.start();
    }

    private void initClient(Session session) throws IOException {
        //send the server version to the client
        session.getRemote().sendBytes(ByteBuffer.wrap(M_VNC_VERSION.getBytes()));
        this.clientState = VncState.SERVER_VERSION_SENT;
    }

    private void initServer(Socket vncSocket) throws IOException {
        DataInputStream is = new DataInputStream(vncSocket.getInputStream());
        DataOutputStream os = new DataOutputStream(vncSocket.getOutputStream());

        handshakeServer(is, os);
        authenticateServer(is, os, vncPassword);
    }

    private void handshakeServer(DataInputStream is, DataOutputStream os) throws IOException {

        byte[] buf = new byte[12];
        is.readFully(buf);
        String rfbProtocol = new String(buf);

        System.out.println(rfbProtocol);

        if (!rfbProtocol.equals(M_VNC_VERSION)) {
            throw new IOException("Server doesn't support VNC 3.8");
        }

        os.write(M_VNC_VERSION.getBytes());
        os.flush();
    }

    private void authenticateServer(DataInputStream is, DataOutputStream os, String vncPassword) throws IOException {

        byte[] b = new byte[2];
        is.readFully(b);
        int authType = b[1];

        System.out.printf("AUth type %d\n", authType);

        switch (authType) {
            case CONNECTION_FAILED: {
                // Server forbids to connect. Read reason and throw exception

                int length = is.readInt();
                byte[] buf = new byte[length];
                is.readFully(buf);
                String reason = new String(buf, CHARSET);
                throw new IOException("Authentication to VNC server is failed. Reason: " + reason);
            }

            case NO_AUTH: {
                // Client can connect without authorization. Nothing to do.
                break;
            }

            case VNC_AUTH: {
                System.out.println("VNC server requires password authentication");
                // respond with selcted auth type
                os.write(b[1]);
                os.flush();
                doVncAuth(is, os, vncPassword);
                break;
            }

            default:
                throw new IOException("Unsupported VNC protocol authorization scheme, scheme code: " + authType + ".");
        }
    }

    @OnWebSocketFrame
    public void onFrame(Frame f) throws IOException {
        System.out.printf("Frame: %d\n", f.getPayloadLength());
        byte[] data = new byte[f.getPayloadLength()];
        f.getPayload().get(data);

        switch (this.clientState) {
            case SERVER_VERSION_SENT:
                //recieve client version, send auth types as 01 01 (no auth)
                System.out.println("Client sent version : " + new String(data, CHARSET));
                this.session.getRemote().sendBytes(ByteBuffer.wrap(M_VNC_AUTH_TYE_NOAUTH));
                this.clientState=VncState.AUTH_TYPES_SENT;
                break;

            case AUTH_TYPES_SENT:
                //recieve auth selected (01) send auth response (OK)
                System.out.printf("Client selected authtype %d\n", data[0]);
                this.session.getRemote().sendBytes(ByteBuffer.wrap(M_VNC_AUTH_OK));
                this.clientState=VncState.AUTH_RESULT_SENT;
                break;
            case AUTH_RESULT_SENT:
                //normal proxy start
                vncSocket.getOutputStream().write(data);
                break;
        }
    }

    /**
     * Encode client password and send it to server.
     */
    private void doVncAuth(DataInputStream is, DataOutputStream os, String password) throws IOException {

        // Read challenge
        byte[] challenge = new byte[16];
        is.readFully(challenge);

        // Encode challenge with password
        byte[] response;
        try {
            response = encodePassword(challenge, password);
        } catch (Exception e) {
            System.out.println("Cannot encrypt client password to send to server: " + e.getMessage());
            throw new IOException("Cannot encrypt client password to send to server: " + e.getMessage());
        }

        // Send encoded challenge
        os.write(response);
        os.flush();

        // Read security result
        int authResult = is.readInt();

        switch (authResult) {
            case VNC_AUTH_OK: {
                // Nothing to do
                break;
            }

            case VNC_AUTH_TOO_MANY:
                System.out.println("Connection to VNC server failed: too many wrong attempts.");
                throw new IOException("Connection to VNC server failed: too many wrong attempts.");

            case VNC_AUTH_FAILED:
                System.out.println("Connection to VNC server failed: wrong password.");
                throw new IOException("Connection to VNC server failed: wrong password.");

            default:
                System.out.println("Connection to VNC server failed, reason code: " + authResult);
                throw new IOException("Connection to VNC server failed, reason code: " + authResult);
        }
    }

    /**
     * Encode password using DES encryption with given challenge.
     *
     * @param challenge
     *            a random set of bytes.
     * @param password
     *            a password
     * @return DES hash of password and challenge
     */
    public byte[] encodePassword(byte[] challenge, String password) throws Exception {
        // VNC password consist of up to eight ASCII characters.
        byte[] key = {0, 0, 0, 0, 0, 0, 0, 0}; // Padding
        byte[] passwordAsciiBytes = password.getBytes(CHARSET);
        System.arraycopy(passwordAsciiBytes, 0, key, 0, Math.min(password.length(), 8));

        // Flip bytes (reverse bits) in key
        for (int i = 0; i < key.length; i++) {
            key[i] = flipByte(key[i]);
        }

        KeySpec desKeySpec = new DESKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] response = cipher.doFinal(challenge);
        return response;
    }

    /**
     * Reverse bits in byte, so least significant bit will be most significant
     * bit. E.g. 01001100 will become 00110010.
     *
     * See also: http://www.vidarholen.net/contents/junk/vnc.html ,
     * http://bytecrafter
     * .blogspot.com/2010/09/des-encryption-as-used-in-vnc.html
     *
     * @param b
     *            a byte
     * @return byte in reverse order
     */
    private static byte flipByte(byte b) {
        int b1_8 = (b & 0x1) << 7;
        int b2_7 = (b & 0x2) << 5;
        int b3_6 = (b & 0x4) << 3;
        int b4_5 = (b & 0x8) << 1;
        int b5_4 = (b & 0x10) >>> 1;
        int b6_3 = (b & 0x20) >>> 3;
        int b7_2 = (b & 0x40) >>> 5;
        int b8_1 = (b & 0x80) >>> 7;
        byte c = (byte)(b1_8 | b2_7 | b3_6 | b4_5 | b5_4 | b6_3 | b7_2 | b8_1);
        return c;
    }
}
