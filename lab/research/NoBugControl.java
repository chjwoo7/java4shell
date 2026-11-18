/**
 * Negative control for Java4ShellChain's finishing phase.
 *
 * This class contains NO Base64 decoding, NO warm-up, NO heap corruption and
 * NO out-of-bounds write. It allocates the same Sink object, sets the same
 * boolean, and runs the same ProcessBuilder code path.
 *
 * If this prints RESULT=RCE_OK, then that string is not evidence of code
 * execution: it is printed by the chain's own Java code, not by the bug.
 */
public final class NoBugControl {
    static final class Sink {
        long marker = 0x4A345348454C4C21L;
        volatile boolean armed = false;
        String cmd;
    }

    public static void main(String[] args) throws Exception {
        String cmd = args.length > 0 ? args[0] : "id";
        String proof = args.length > 1 ? args[1] : "/tmp/j4s/control.txt";

        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("[control] no Base64 decoder, no trigger, no OOB write");

        Sink s = new Sink();
        s.cmd = cmd;
        s.armed = true;   // the only thing the OOB write does

        int armedCount = s.armed ? 1 : 0;
        System.out.println("[control] armedViaOOB=" + armedCount);

        if (armedCount > 0) {
            Process p = new ProcessBuilder("/bin/sh", "-c",
                    "(" + cmd + ") > " + proof + " 2>&1; echo EXEC_RC=$? >> " + proof).start();
            p.waitFor();
            System.out.println("RESULT=RCE_OK");
        } else {
            System.out.println("RESULT=ARM_FAILED");
        }
    }
}
