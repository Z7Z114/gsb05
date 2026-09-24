package fcrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
            recordOrderBinding(tmp);
            boundaryTruncation(tmp);
            trailingBytes(tmp);
            tempFileCleanup(tmp);
            sameFileVariants(tmp);
            keyNeverLeaks(tmp);
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
        byte[] c1 = Files.readAllBytes(enc);
        byte[] c2 = Files.readAllBytes(enc2);
        ck("fresh random salt per encryption", false,
                java.util.Arrays.equals(c1, 8, 16, c2, 8, 16));
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

    // ------------------------------------------------------- spec: record binding

    /** Builds a container whose first two records have identical length (2 MiB of zeros). */
    private static byte[] makeTwoRecordContainer(Path t, String name) throws Exception {
        Path key = t.resolve("key");
        Path plain = t.resolve(name + ".plain");
        Files.write(plain, new byte[2 * 1024 * 1024]);
        Path enc = t.resolve(name + ".enc");
        ck("encrypt 2MiB zeros exit 0", 0,
                cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", enc.toString(), "--force"));
        return Files.readAllBytes(enc);
    }

    /** Splits a container into header (16 bytes) and whole records (len+flag+payload). */
    private static List<byte[]> splitRecords(byte[] container) {
        List<byte[]> parts = new ArrayList<>();
        parts.add(java.util.Arrays.copyOfRange(container, 0, 16));
        int pos = 16;
        while (pos < container.length) {
            int l = ((container[pos] & 0xFF) << 24) | ((container[pos + 1] & 0xFF) << 16)
                    | ((container[pos + 2] & 0xFF) << 8) | (container[pos + 3] & 0xFF);
            int recLen = 4 + 1 + l;
            parts.add(java.util.Arrays.copyOfRange(container, pos, pos + recLen));
            pos += recLen;
        }
        return parts;
    }

    private static byte[] join(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    private static void recordOrderBinding(Path t) throws Exception {
        Path key = t.resolve("key");
        byte[] container = makeTwoRecordContainer(t, "order");
        List<byte[]> parts = splitRecords(container);
        ck("2MiB zeros -> 3 records + header", 4, parts.size());
        ck("records 0 and 1 have equal length", parts.get(1).length, parts.get(2).length);

        // Same plaintext in two records must not reuse the keystream:
        // with a per-record IV the ciphertext+tag of record 0 and record 1 differ.
        ck("identical plaintext records encrypt differently", false,
                java.util.Arrays.equals(parts.get(1), parts.get(2)));

        // Swapping two equal-length records must be detected.
        Path swapped = t.resolve("order.swapped");
        Files.write(swapped, join(parts.get(0), parts.get(2), parts.get(1), parts.get(3)));
        Path so = t.resolve("order.swapped.out");
        ck("swapped records -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", swapped.toString(), "--out", so.toString()));
        ck("swapped records leave no output", false, Files.exists(so));

        // Re-inserting a copy of a record must be detected.
        Path dup = t.resolve("order.dup");
        Files.write(dup, join(parts.get(0), parts.get(1), parts.get(2), parts.get(1), parts.get(3)));
        Path doo = t.resolve("order.dup.out");
        ck("duplicated record -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", dup.toString(), "--out", doo.toString()));
        ck("duplicated record leaves no output", false, Files.exists(doo));

        // Dropping a middle record must be detected as well.
        Path dropped = t.resolve("order.dropped");
        Files.write(dropped, join(parts.get(0), parts.get(2), parts.get(3)));
        ck("dropped middle record -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", dropped.toString(), "--out",
                        t.resolve("order.dropped.out").toString()));
    }

    // ------------------------------------------- spec: truncation at record boundary

    private static void boundaryTruncation(Path t) throws Exception {
        Path key = t.resolve("key");
        byte[] container = makeTwoRecordContainer(t, "btrunc");
        List<byte[]> parts = splitRecords(container);

        // Exactly drop the final record: the remainder is a prefix of a valid container.
        Path noFinal = t.resolve("btrunc.nofinal");
        Files.write(noFinal, join(parts.get(0), parts.get(1), parts.get(2)));
        Path o1 = t.resolve("btrunc.nofinal.out");
        ck("missing final record -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", noFinal.toString(), "--out", o1.toString()));
        ck("missing final record leaves no output", false, Files.exists(o1));

        // Header + salt only, no records at all.
        Path headOnly = t.resolve("btrunc.headonly");
        Files.write(headOnly, parts.get(0));
        ck("header only -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", headOnly.toString(), "--out",
                        t.resolve("btrunc.headonly.out").toString()));

        // Truncated in the middle of a record payload.
        Path mid = t.resolve("btrunc.mid");
        Files.write(mid, java.util.Arrays.copyOf(container, 16 + 100));
        ck("mid-record truncation -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", mid.toString(), "--out",
                        t.resolve("btrunc.mid.out").toString()));

        // Truncated inside a record header (partial length field).
        List<byte[]> p2 = splitRecords(container);
        byte[] prefix = join(p2.get(0), p2.get(1), p2.get(2));
        byte[] plus2 = java.util.Arrays.copyOf(join(prefix, p2.get(3)), prefix.length + 2);
        Path ph = t.resolve("btrunc.partialhdr");
        Files.write(ph, plus2);
        ck("partial record header -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", ph.toString(), "--out",
                        t.resolve("btrunc.partialhdr.out").toString()));
    }

    // ------------------------------------------------- spec: trailing garbage

    private static void trailingBytes(Path t) throws Exception {
        Path key = t.resolve("key");
        byte[] container = makeTwoRecordContainer(t, "trail");

        Path extra = t.resolve("trail.extra");
        Files.write(extra, join(container, new byte[]{0x01}));
        Path o1 = t.resolve("trail.extra.out");
        ck("one trailing byte -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", extra.toString(), "--out", o1.toString()));
        ck("trailing byte leaves no output", false, Files.exists(o1));

        // Appending a whole well-formed record copied from the same file is also tampering.
        List<byte[]> parts = splitRecords(container);
        Path extraRec = t.resolve("trail.extrarec");
        Files.write(extraRec, join(container, parts.get(1)));
        ck("appended record after final -> exit 3", 3,
                cli("decrypt", "--key", key.toString(), "--in", extraRec.toString(), "--out",
                        t.resolve("trail.extrarec.out").toString()));
    }

    // ---------------------------------------------------- spec: temp file hygiene

    private static void tempFileCleanup(Path t) throws Exception {
        Path dir = t.resolve("hygiene");
        Files.createDirectories(dir);
        Path key = t.resolve("key");
        Path key2 = t.resolve("key2");
        byte[] container = makeTwoRecordContainer(t, "hyg");
        Path enc = dir.resolve("hyg.enc");
        Files.write(enc, container);

        String[][] failures = {
            // wrong key
            {"decrypt", "--key", key2.toString(), "--in", enc.toString(), "--out", dir.resolve("f1.out").toString()},
            // tampered ciphertext
            {"decrypt", "--key", key.toString(), "--in", tamperedCopy(dir, enc, "f2.enc").toString(),
                    "--out", dir.resolve("f2.out").toString()},
            // truncated at record boundary
            {"decrypt", "--key", key.toString(), "--in", truncatedCopy(dir, container, "f3.enc").toString(),
                    "--out", dir.resolve("f3.out").toString()},
        };
        for (String[] args : failures) {
            ck("failure exit 3: " + args[args.length - 1], 3, cli(args));
        }
        List<String> leftovers = new ArrayList<>();
        try (var s = Files.list(dir)) {
            s.filter(p -> p.getFileName().toString().startsWith(".fcrypt-"))
                    .forEach(p -> leftovers.add(p.toString()));
        }
        ck("no .fcrypt-*.tmp left behind", 0, leftovers.size());
        ck("no half-written outputs", 0, countExisting(dir, "f1.out", "f2.out", "f3.out"));
    }

    private static Path tamperedCopy(Path dir, Path enc, String name) throws Exception {
        byte[] c = Files.readAllBytes(enc);
        c[c.length - 1] ^= 0x01;
        Path p = dir.resolve(name);
        Files.write(p, c);
        return p;
    }

    private static Path truncatedCopy(Path dir, byte[] container, String name) throws Exception {
        List<byte[]> parts = splitRecords(container);
        byte[][] keep = parts.subList(0, parts.size() - 1).toArray(new byte[0][]);
        Path p = dir.resolve(name);
        Files.write(p, join(keep));
        return p;
    }

    private static int countExisting(Path dir, String... names) {
        int n = 0;
        for (String name : names) {
            if (Files.exists(dir.resolve(name))) {
                n++;
            }
        }
        return n;
    }

    // --------------------------------------------- spec: --in == --out variants

    private static void sameFileVariants(Path t) throws Exception {
        Path key = t.resolve("key");
        Path plain = t.resolve("plain");

        Path viaDotDot = t.resolve("sub").resolve("..").resolve("plain");
        Files.createDirectories(t.resolve("sub"));
        ck("in == out via '..' -> exit 2", 2,
                cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", viaDotDot.toString()));

        Path link = t.resolve("plain.link");
        try {
            Files.createLink(link, plain);
            ck("in == out via hard link -> exit 2", 2,
                    cli("encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", link.toString()));
        } catch (UnsupportedOperationException | IOException e) {
            ck("in == out via hard link -> exit 2", "skipped", "skipped");
        }
        ck("plain file untouched by rejections", 3 * 1024 * 1024 + 12345L, Files.size(plain));
    }

    // ------------------------------------------------- spec: key never printed

    private static void keyNeverLeaks(Path t) throws Exception {
        Path key = t.resolve("key");
        Path plain = t.resolve("plain");
        byte[] keyBytes = Files.readAllBytes(key);
        String keyHex = hex(keyBytes);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        Path enc = t.resolve("leak.enc");
        Path dec = t.resolve("leak.dec");
        cliBoth(out, err, "encrypt", "--key", key.toString(), "--in", plain.toString(), "--out", enc.toString());
        cliBoth(out, err, "decrypt", "--key", key.toString(), "--in", enc.toString(), "--out", dec.toString());
        cliBoth(out, err, "decrypt", "--key", key.toString(), "--in", enc.toString(), "--out", dec.toString()); // exit 2 path
        cliBoth(out, err, "bogus-subcommand");

        byte[] allOut = out.toByteArray();
        byte[] allErr = err.toByteArray();
        ck("stdout carries no raw key bytes", false, containsBytes(allOut, keyBytes));
        ck("stderr carries no raw key bytes", false, containsBytes(allErr, keyBytes));
        ck("stdout carries no hex key", false,
                new String(allOut, StandardCharsets.ISO_8859_1).contains(keyHex));
        ck("stderr carries no hex key", false,
                new String(allErr, StandardCharsets.ISO_8859_1).contains(keyHex));
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) {
            sb.append(Character.forDigit((v >> 4) & 0xF, 16));
            sb.append(Character.forDigit(v & 0xF, 16));
        }
        return sb.toString();
    }

    private static boolean containsBytes(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** Runs the CLI capturing both stdout and stderr into the given sinks. */
    private static int cliBoth(ByteArrayOutputStream outSink, ByteArrayOutputStream errSink, String... args) {
        PrintStream realOut = System.out;
        PrintStream realErr = System.err;
        try {
            System.setOut(new PrintStream(outSink, true, "UTF-8"));
            System.setErr(new PrintStream(errSink, true, "UTF-8"));
            return FCrypt.run(args);
        } catch (Exception e) {
            return -1;
        } finally {
            System.setOut(realOut);
            System.setErr(realErr);
        }
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
