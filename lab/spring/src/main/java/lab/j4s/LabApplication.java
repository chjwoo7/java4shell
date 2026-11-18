package lab.j4s;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring Boot target for CVE-2026-114938.
 *
 * The exploit path is entirely remote: an HTTP request carrying a malformed
 * Basic header makes the AVX-512 Base64 intrinsic write 62 bytes past the
 * decode buffer, corrupting the Principal allocated immediately after it.
 * The request then passes the admin gate and the application runs the command
 * it was asked to run.
 *
 * /api/run is a deliberately dangerous administrative diagnostic endpoint
 * (the kind of thing that exists behind an admin flag in real products). The
 * Base64 overflow is what turns "no privileges" into "admin".
 *
 * Nothing in this file calls the decoder with attacker data in a special way:
 * the pattern is a credentials buffer (capped at 64 bytes) plus a per-request
 * authority object, allocated back to back on the request thread.
 */
@SpringBootApplication
public class LabApplication {

    /** Per-request authority. volatile so the gate is a real load, not a folded constant. */
    static final class Principal {
        volatile boolean admin;
        String user = "anonymous";
    }

    /**
     * Keeps the per-request authority object reachable.
     *
     * Without this C2 can scalar-replace Principal and constant-fold
     * `principal.admin` to false, removing the allocation entirely and with
     * it the object the overflow is meant to land on. Writing it to a static
     * forces a real heap allocation at the right point in the request.
     */
    static volatile Object LAST;

    /** Determines whether the app runs a diagnostic command. */
    static class Diag {
        ProcessBuilder builder;
    }

    public static void main(String[] args) {
        SpringApplication.run(LabApplication.class, args);
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
                .requestMatchers("/health", "/api/**").permitAll()
                .anyRequest().authenticated());
        http.csrf(c -> c.disable());
        return http.build();
    }

    @RestController
    static class Endpoints {

        @GetMapping("/health")
        String health() {
            return "ok";
        }

        @GetMapping("/whoami")
        String whoami(org.springframework.security.core.Authentication a) {
            return "authenticated as " + a.getName();
        }

        /**
         * Administrative diagnostic runner.
         *
         * Realistic shape: credentials are decoded into a fixed buffer sized
         * for the maximum credential length, and a per-request authority
         * object is created on the same thread. If the request holds admin
         * authority, the diagnostic command runs.
         */
        @PostMapping("/api/run")
        String run(@RequestHeader(value = "Authorization", required = false) String auth,
                   @RequestParam(value = "cmd", required = false) String cmd) throws Exception {

            byte[] creds = new byte[65];
            Principal principal = new Principal();
            LAST = principal;

            // Decode AFTER both allocations: the decode buffer and the
            // authority object must be neighbours for the 62-byte spill to
            // reach the authority header. The decoder allocates internally,
            // so decoding first would push the authority out of range.
            String b64 = auth == null ? null
                    : (auth.regionMatches(true, 0, "Basic ", 0, 6) ? auth.substring(6) : auth);
            byte[] src = b64 == null ? null : b64.getBytes(StandardCharsets.ISO_8859_1);
            if (src != null) {
                try {
                    Base64.getDecoder().decode(src, creds);
                } catch (IllegalArgumentException bad) {
                    // Rejected, but the intrinsic already wrote its 64 bytes.
                }
            }

            if (!principal.admin) {
                return "denied: privilege=user\n";
            }
            if (cmd == null || cmd.isEmpty()) {
                return "denied: no command\n";
            }

            Process p = new ProcessBuilder("/bin/sh", "-c", cmd).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            return "admin: privilege=admin\n--- output ---\n" + out;
        }

        /** Diagnostic: reports the authority state without running anything. */
        @PostMapping("/api/probe")
        String probe(@RequestHeader(value = "Authorization", required = false) String auth) {
            byte[] creds = new byte[65];
            Principal principal = new Principal();
            int decoded = -1;
            if (auth != null) {
                String b64 = auth.regionMatches(true, 0, "Basic ", 0, 6) ? auth.substring(6) : auth;
                try {
                    decoded = Base64.getDecoder().decode(
                            b64.getBytes(StandardCharsets.ISO_8859_1), creds);
                } catch (IllegalArgumentException bad) {
                    decoded = -2;
                }
            }
            return "admin=" + principal.admin + " decoded=" + decoded
                    + " creds[0]=" + (creds[0] & 0xff) + "\n";
        }
    }
}
