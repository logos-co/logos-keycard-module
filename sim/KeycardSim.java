import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import javacard.framework.Applet;

/**
 * A Keycard in jCardSim, running the Keycard applets as built from their source, its APDUs served
 * over TCP: each one length-prefixed, its answer the data's length, the data and the status word.
 * The pseudo-APDU FF 7F 00 00 swaps in a factory-fresh card.
 */
public class KeycardSim {
  private static final byte[] PKG = {(byte) 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01};
  private static final byte[] FRESH = {(byte) 0xFF, 0x7F, 0x00, 0x00};
  private static final byte[] OK = {(byte) 0x90, 0x00};

  private static byte[] aid(int applet, boolean instance) {
    byte[] a = Arrays.copyOf(PKG, PKG.length + (instance ? 2 : 1));
    a[PKG.length] = (byte) applet;
    if (instance) a[PKG.length + 1] = 1;
    return a;
  }

  @SuppressWarnings("unchecked")
  private static void install(CardSimulator sim, int applet, String name, byte[] instance, byte[] tail)
      throws ClassNotFoundException {
    Class<? extends Applet> cls;
    try {
      cls = (Class<? extends Applet>) Class.forName("im.status.keycard." + name);
    } catch (ClassNotFoundException e) {
      if (name.equals("IdentApplet")) return; // 3.x cards have no identity applet
      throw e;
    }
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    b.write(instance.length);
    b.write(instance, 0, instance.length);
    b.write(tail, 0, tail.length);
    byte[] p = b.toByteArray();
    sim.installApplet(AIDUtil.create(aid(applet, false)), cls, p, (short) 0, (byte) p.length);
  }

  private static CardSimulator card() throws ClassNotFoundException {
    CardSimulator sim = new CardSimulator();
    byte[] small = {0x01, 0x00, 0x02, (byte) 0xC9, 0x00};
    byte[] ndef = {(byte) 0xD2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};
    install(sim, 1, "KeycardApplet", aid(1, true), new byte[0]);
    install(sim, 2, "NDEFApplet", ndef, small);
    install(sim, 3, "CashApplet", aid(3, true), small);
    install(sim, 4, "IdentApplet", aid(4, true), small);
    return sim;
  }

  public static void main(String[] args) throws Exception {
    int port = Integer.parseInt(args[0]);
    CardSimulator sim = card();
    ServerSocket server = new ServerSocket(port, 8, InetAddress.getByName("127.0.0.1"));
    System.out.println("listening 127.0.0.1:" + server.getLocalPort());
    System.out.flush();
    while (true) {
      try (Socket s = server.accept()) {
        s.setTcpNoDelay(true);
        DataInputStream in = new DataInputStream(s.getInputStream());
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
        while (true) {
          int len;
          try {
            len = in.readInt();
          } catch (EOFException e) {
            break;
          }
          byte[] apdu = new byte[len];
          in.readFully(apdu);
          byte[] r;
          if (Arrays.equals(apdu, FRESH)) {
            sim = card();
            r = OK;
          } else {
            r = sim.transmitCommand(apdu);
          }
          out.writeInt(r.length - 2);
          out.write(r);
          out.flush();
        }
      } catch (Exception e) {
        System.err.println("session: " + e);
      }
    }
  }
}
