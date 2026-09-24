package fcrypt;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Smoke tests for filecrypt.
 *
 * Run with:
 *   javac -encoding UTF-8 -d out fcrypt/*.java
 *   java -cp out fcrypt.TestFCrypt
 *
 * These cover the ordinary paths only. They are not a complete check of the
 * behaviour spec in README.md -- passing them does not mean the tool is correct.
 */
public final class TestFCrypt {

    private static int pass = 0;
    private static final List<String> failures = new ArrayList<>();
    private static final SecureRandom RND = new SecureRandom();

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("fcrypt-visible-");
        try {
            genkey(tmp);
            roundtrip(tmp);
            empties(tmp);
            rejections(tmp);
            argumentErrors(tmp);
            authFailureLeavesNoOutput(tmp);
        } finally {
            deleteTree(tmp);
        }
        System.out.println("---- pass=" + pass + " fail=" + failures.size());
        for (String f : failures) {
            System.out.println("FAIL " + f);
        }
        if (!failures.isEmpty()) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------- test cases

    private static void genkey(Path t) throws Exception {
        Path key = t.resolve("key");
        ck("genkey exit 0", 0, cli("genkey", key.toString()));
        ck("key is 32 bytes", 32L, Files.exists(key) ? Files.size(key) : -1L);
        ck("genkey refuses to overwrite", 2, cli("genkey", key.toString()));
        ck("genkey needs exactly one path", 2, cli("genkey"));
    }

    private static void roundtrip(Path t) throws Exception {
        Path key = t.resolve("key");
        Path plain = t.resolve("plain");
        byte[] body = new byte[3 * 1024 * 1024 + 12345];
        RND.nextBytes(body);
        Files.write(plain, body);

        Path enc = t.resolve("enc");
        ck("encrypt exit 0", 0, cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", enc.toString()));
        ck("magic header", "FCRYPT01", new String(Files.readAllBytes(enc), 0, 8, StandardCharsets.US_ASCII));

        Path dec = t.resolve("dec");
        ck("decrypt exit 0", 0, cli("decrypt", "--key", key.toString(), "--in", enc.toString(), "--out", dec.toString()));
        ck("roundtrip identical", true, java.util.Arrays.equals(body, Files.readAllBytes(dec)));

        Path enc2 = t.resolve("enc2");
        cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", enc2.toString());
        ck("two encryptions differ", false, java.util.Arrays.equals(Files.readAllBytes(enc), Files.readAllBytes(enc2)));
    }

    private static void empties(Path t) throws Exception {
        Path key = t.resolve("key");
        Path empty = t.resolve("empty");
        Files.write(empty, new byte[0]);
        Path e = t.resolve("empty.enc");
        Path d = t.resolve("empty.dec");
        ck("encrypt empty exit 0", 0, cli("encrypt", "--key", key.toString(), "--in", empty.toString(), "--out", e.toString()));
        ck("decrypt empty exit 0", 0, cli("decrypt", "--key", key.toString(), "--in", e.toString(), "--out", d.toString()));
        ck("empty roundtrip is 0 bytes", 0L, Files.size(d));
    }

    private static void rejections(Path t) throws Exception {
        Path key = t.resolve("key");
        Path enc = t.resolve("enc");

        Path key2 = t.resolve("key2");
        cli("genkey", key2.toString());
        Path w = t.resolve("wrong.out");
        ck("wrong key -> exit 3", 3, cli("decrypt", "--key", key2.toString(), "--in", enc.toString(), "--out", w.toString()));
        ck("wrong key leaves no output", false, Files.exists(w));

        Path tam = t.resolve("tampered");
        byte[] c = Files.readAllBytes(enc);
        c[100] ^= 0x5A;
        Files.write(tam, c);
        Path to = t.resolve("tampered.out");
        ck("tampered ciphertext -> exit 3", 3, cli("decrypt", "--key", key.toString(), "--in", tam.toString(), "--out", to.toString()));
        ck("tampered leaves no output", false, Files.exists(to));

        Path trunc = t.resolve("truncated.header");
        Files.write(trunc, java.util.Arrays.copyOf(c, 20));
        ck("truncated header -> exit 3", 3, cli("decrypt", "--key", key.toString(), "--in", trunc.toString(), "--out", t.resolve("th.out").toString()));

        byte[] rnd = new byte[100];
        RND.nextBytes(rnd);
        Path random = t.resolve("random");
        Files.write(random, rnd);
        ck("random input -> exit 4", 4, cli("decrypt", "--key", key.toString(), "--in", random.toString(), "--out", t.resolve("r.out").toString()));

        Path short5 = t.resolve("short5");
        Files.write(short5, java.util.Arrays.copyOf(c, 5));
        ck("shorter than magic -> exit 4", 4, cli("decrypt", "--key", key.toString(), "--in", short5.toString(), "--out", t.resolve("s.out").toString()));

        Path zero = t.resolve("zero");
        Files.write(zero, new byte[0]);
        ck("zero-byte input -> exit 4", 4, cli("decrypt", "--key", key.toString(), "--in", zero.toString(), "--out", t.resolve("z.out").toString()));
    }

    private static void argumentErrors(Path t) throws Exception {
        Path key = t.resolve("key");
        Path plain = t.resolve("plain");
        Path enc = t.resolve("enc");

        Path k16 = t.resolve("key16");
        Files.write(k16, bytes(16));
        ck("short key -> exit 2", 2, cli("encrypt", "--key", k16.toString(), "--in", plain.toString(), "--out", t.resolve("x.out").toString()));
        Path k33 = t.resolve("key33");
        Files.write(k33, bytes(33));
        ck("33-byte key -> exit 2", 2, cli("encrypt", "--key", k33.toString(), "--in", plain.toString(), "--out", t.resolve("x.out").toString()));

        ck("existing output without --force -> exit 2", 2, cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", enc.toString()));
        ck("--force overwrites -> exit 0", 0, cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", enc.toString(), "--force"));
        ck("in == out -> exit 2", 2, cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", plain.toString()));
        ck("missing input -> exit 2", 2, cli("encrypt", "--key", key.toString(), "--in", t.resolve("nope").toString(), "--out", t.resolve("x.out").toString()));
        ck("missing --out -> exit 2", 2, cli("encrypt", "--key", key.toString(), "--in", plain.toString()));
        ck("unknown flag -> exit 2", 2, cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", t.resolve("x.out").toString(), "--bogus"));
        ck("missing output directory -> exit 2", 2, cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", t.resolve("nodir").resolve("x.out").toString()));
        ck("unknown subcommand -> exit 2", 2, cli("bogus"));
        ck("no arguments -> exit 2", 2, cli());
    }

    private static void authFailureLeavesNoOutput(Path t) throws Exception {
        Path dir = t.resolve("authfail");
        Files.createDirectories(dir);
        Path key = t.resolve("key");
        Path enc = t.resolve("enc");
        Path key2 = t.resolve("key2");
        Path out = dir.resolve("authtmp.out");
        int rc = cli("decrypt", "--key", key2.toString(), "--in", enc.toString(), "--out", out.toString());
        ck("wrong key -> exit 3", 3, rc);
        ck("no output left after an authentication failure", false, Files.exists(out));
    }

    // ---------------------------------------------------------------- helpers

    /** Runs the CLI in-process and returns its exit code, with stderr captured. */
    private static int cli(String... args) {
        PrintStream realErr = System.err;
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(sink, true, "UTF-8"));
            return FCrypt.run(args);
        } catch (Exception e) {
            return -1;
        } finally {
            System.setErr(realErr);
        }
    }

    private static byte[] bytes(int n) {
        byte[] b = new byte[n];
        RND.nextBytes(b);
        return b;
    }

    private static void ck(String name, Object want, Object got) {
        if (String.valueOf(want).equals(String.valueOf(got))) {
            pass++;
        } else {
            failures.add(name + " (want " + want + " got " + got + ")");
        }
    }

    private static void deleteTree(Path root) {
        try (var s = Files.walk(root)) {
            s.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                }
            });
        } catch (Exception ignored) {
        }
    }

    private TestFCrypt() {}
}
