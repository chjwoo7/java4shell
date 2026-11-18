import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Minimal, unambiguous check. One dst[65] then one vic[64], back to back.
 * Prints the victim header before and after the trigger, reading the length
 * BOTH through Java and through Unsafe, and dumping raw bytes.
 */
public final class OneShot {
    private static volatile int sink;
    private static sun.misc.Unsafe u;

    static long addr(Object o) {
        Object[] a = new Object[] { o };
        return u.getLong(a, u.arrayBaseOffset(Object[].class));
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

        byte[] dst = new byte[65];
        byte[] vic = new byte[64];
        Arrays.fill(vic, (byte) 0x5a);

        long d0 = addr(dst), v0 = addr(vic);
        System.out.printf("dst=0x%x vic=0x%x  vic-dst=%d%n", d0, v0, v0 - d0);
        System.out.printf("before: java.len=%d unsafe.len=%d mark=0x%016x klass=0x%08x%n",
                vic.length, u.getInt(vic, 12), u.getLong(vic, 0), u.getInt(vic, 8));

        boolean rej = false;
        try { d.decode(bad, dst); } catch (IllegalArgumentException e) { rej = true; }

        int javaLen;
        try { javaLen = vic.length; } catch (Throwable t) { javaLen = -1; }
        System.out.printf("after : rejected=%s java.len=%d unsafe.len=%d mark=0x%016x klass=0x%08x%n",
                rej, javaLen, u.getInt(vic, 12), u.getLong(vic, 0), u.getInt(vic, 8));

        StringBuilder sb = new StringBuilder();
        for (long i = 0; i < 24; i++) sb.append(String.format("%02x ", u.getByte(vic, i) & 0xff));
        System.out.println("vic[0..23] = " + sb);

        // also show the destination's own tail to prove the spill source
        StringBuilder sb2 = new StringBuilder();
        for (long i = 44; i < 80; i++) sb2.append(String.format("%02x ", u.getByte(dst, i) & 0xff));
        System.out.println("dst[44..79]= " + sb2);
    }
}
