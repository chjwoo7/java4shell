import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Measures the true allocation neighbours of the decode buffer without
 * perturbing them.
 *
 * The address helper reuses ONE preallocated Object[] box: the earlier version
 * allocated a fresh Object[1] per call, which inserted allocations between the
 * objects being measured and produced a bogus 1808-byte gap.
 */
public final class Layout2 {
    private static volatile int sink;
    private static sun.misc.Unsafe u;
    private static final Object[] BOX = new Object[1];
    private static long boxBase;

    static final class Principal {
        volatile boolean admin;
        String user = "anonymous";
    }

    static long addr(Object o) {
        BOX[0] = o;
        return u.getLong(BOX, boxBase);
    }

    public static void main(String[] a) throws Exception {
        Field uf = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        u = (sun.misc.Unsafe) uf.get(null);
        boxBase = u.arrayBaseOffset(Object[].class);

        Base64.Decoder d = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] warm = new byte[4096];
        for (int i = 0; i < 200_000; i++) sink += d.decode(valid, warm);

        // --- measure a clean pair ---
        byte[] creds = new byte[65];
        Principal p = new Principal();
        long ca = addr(creds), pa = addr(p);
        System.out.printf("[pair] creds=0x%x principal=+%d%n", ca, pa - ca);

        // --- what does a 65-byte array actually occupy? ---
        byte[] x = new byte[65];
        byte[] y = new byte[65];
        System.out.printf("[size] 65-byte array stride = %d%n", addr(y) - addr(x));

        byte[] o1 = new byte[64];
        byte[] o2 = new byte[64];
        System.out.printf("[size] 64-byte array stride = %d%n", addr(o2) - addr(o1));

        // --- object size probes ---
        Principal a1 = new Principal();
        Principal a2 = new Principal();
        System.out.printf("[size] Principal stride = %d%n", addr(a2) - addr(a1));

        // --- interleaved, as a request handler does it ---
        System.out.println("[interleaved] creds[i] then Principal[i]:");
        for (int i = 0; i < 6; i++) {
            byte[] c = new byte[65];
            Principal q = new Principal();
            System.out.printf("  #%d gap=%d%n", i, addr(q) - addr(c));
        }

        // --- what if creds is allocated, then principal, with a decode between? ---
        System.out.println("[interleaved+decode] creds, decode, Principal:");
        byte[] bad = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < 3; i++) {
            for (int k = 0; k < 50_000; k++) sink += d.decode(valid, warm);
            byte[] c = new byte[65];
            try { d.decode(bad, c); } catch (IllegalArgumentException e) { }
            Principal q = new Principal();
            System.out.printf("  #%d gap=%d%n", i, addr(q) - addr(c));
        }
    }
}
