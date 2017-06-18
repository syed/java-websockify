import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.websocket.server.WebSocketHandler;


/**
 * Created by syed on 6/17/17.
 */
public class WSServer {
    public static void main(String[] args) throws Exception {
        /* HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/websockify", new WsHandler());
        server.start();*/

        Server server = new Server(8000);
        WebSocketHandler wsHandler = new WsHandler();

        server.setHandler(wsHandler);
        server.start();
        server.join();
    }
}
