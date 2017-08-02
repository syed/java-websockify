import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketFrame;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;
import org.eclipse.jetty.websocket.api.extensions.Frame;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;

// http://jansipke.nl/websocket-tutorial-with-java-server-jetty-and-javascript-client/

@WebSocket
public class WsHandler extends WebSocketHandler {

    Socket vncSocket;
    int vncPort = 5900;
    String vncPassword = "password";

    enum clientState {
        INIT, SERVER_VERSION_SENT, CLIENT_VERSION_RECIEVED, AUTH_TYPES_SENT,
    }


    @Override
    public void configure(WebSocketServletFactory webSocketServletFactory) {
        webSocketServletFactory.register(WsHandler.class);
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
        System.out.println("Connect: " + session.getRemoteAddress().getAddress());
        System.out.println(session.getUpgradeRequest().getRequestURI());

        vncSocket = new Socket("127.0.0.1", vncPort);
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

    @OnWebSocketFrame
    public void onFrame(Frame f) throws IOException {
        System.out.printf("Frame: %d\n", f.getPayloadLength());
        byte[] data = new byte[f.getPayloadLength()];
        f.getPayload().get(data);
        vncSocket.getOutputStream().write(data);
    }
}
