package fcrypt;

import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * filecrypt: streaming AES-256-GCM file encryption tool.
 *
 * Exit codes:
 *   0 success
 *   2 usage / environment error (bad args, bad key length, unreadable input,
 *     output exists without --force, ...)
 *   3 authentication failure (wrong key, tampered or truncated ciphertext)
 *   4 not a filecrypt file (bad magic, or shorter than the 8-byte magic)
 */
public final class FCrypt {

    static final byte[] MAGIC = {'F', 'C', 'R', 'Y', 'P', 'T', '0', '1'};
    static final int KEY_LEN = 32;          // AES-256
    static final int SALT_LEN = 8;          // random per encryption
    static final int IV_LEN = 12;           // GCM standard IV
    static final int TAG_LEN = 16;          // GCM tag, appended to each chunk
    static final int CHUNK = 1 << 20;       // 1 MiB plaintext per chunk
    static final int FLAG_FINAL = 1;

    static final int EXIT_OK = 0;
    static final int EXIT_USAGE = 2;
    static final int EXIT_AUTH = 3;
    static final int EXIT_NOT_OURS = 4;

    private FCrypt() {}

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        if (args.length < 1) {
            return usage();
        }
        String cmd = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        try {
            switch (cmd) {
                case "genkey":
                    return cmdGenkey(rest);
                case "encrypt":
                    return cmdCrypt(rest, true);
                case "decrypt":
                    return cmdCrypt(rest, false);
                default:
                    err("unknown subcommand: " + cmd);
                    return usage();
            }
        } catch (UsageException e) {
            err(e.getMessage());
            return EXIT_USAGE;
        } catch (NotOursException e) {
            err(e.getMessage());
            return EXIT_NOT_OURS;
        } catch (AuthException e) {
            err(e.getMessage());
            return EXIT_AUTH;
        } catch (IOException e) {
            err("I/O error: " + e.getMessage());
            return EXIT_USAGE;
        } catch (GeneralSecurityException e) {
            err("crypto error: " + e.getMessage());
            return EXIT_USAGE;
        }
    }

    private static int usage() {
        err("usage:");
        err("  fcrypt genkey <key-file>");
        err("  fcrypt encrypt --key <key-file> --in <in> --out <out> [--force]");
        err("  fcrypt decrypt --key <key-file> --in <in> --out <out> [--force]");
        return EXIT_USAGE;
    }

    // ---------------------------------------------------------------- genkey

    private static int cmdGenkey(String[] args) throws IOException, UsageException {
        if (args.length != 1) {
            throw new UsageException("genkey takes exactly one output path");
        }
        Path out = Path.of(args[0]);
        if (Files.exists(out)) {
            throw new UsageException("output already exists (refusing to overwrite a key): " + out);
        }
        checkParentDir(out);

        byte[] key = new byte[KEY_LEN];
        new SecureRandom().nextBytes(key);
        Path tmp = null;
        try {
            tmp = Files.createTempFile(parentOrCwd(out), ".fcrypt-", ".tmp");
            try (OutputStream os = Files.newOutputStream(tmp,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                os.write(key);
            }
            moveIntoPlace(tmp, out, false);
            tmp = null;
        } finally {
            Arrays.fill(key, (byte) 0);
            deleteQuietly(tmp);
        }
        return EXIT_OK;
    }

    // ------------------------------------------------------- encrypt/decrypt

    private static int cmdCrypt(String[] args, boolean encrypt)
            throws IOException, UsageException, NotOursException, AuthException, GeneralSecurityException {
        Path keyPath = null, in = null, out = null;
        boolean force = false;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--key":
                    keyPath = Path.of(requireValue(args, ++i, a));
                    break;
                case "--in":
                    in = Path.of(requireValue(args, ++i, a));
                    break;
                case "--out":
                    out = Path.of(requireValue(args, ++i, a));
                    break;
                case "--force":
                    force = true;
                    break;
                default:
                    throw new UsageException("unknown argument: " + a);
            }
        }
        if (keyPath == null || in == null || out == null) {
            throw new UsageException("encrypt/decrypt require --key, --in and --out");
        }

        byte[] key = readKey(keyPath);
        try {
            checkInput(in);
            checkOutput(in, out, force);

            Path tmp = Files.createTempFile(parentOrCwd(out), ".fcrypt-", ".tmp");
            if (encrypt) {
                encryptFile(key, in, tmp);
            } else {
                decryptFile(key, in, tmp);
            }
            moveIntoPlace(tmp, out, force);
            deleteQuietly(tmp);
            return EXIT_OK;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static void encryptFile(byte[] key, Path in, Path tmp)
            throws IOException, GeneralSecurityException {
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt);

        byte[] plain = new byte[CHUNK];
        try (InputStream is = Files.newInputStream(in, StandardOpenOption.READ);
             OutputStream os = new java.io.BufferedOutputStream(Files.newOutputStream(tmp,
                     StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING))) {
            os.write(MAGIC);
            os.write(salt);

            long index = 0;
            for (;;) {
                int n = readUpTo(is, plain);
                if (n < 0) {
                    n = 0; // EOF before any byte: empty final chunk
                }
                boolean fin = n < CHUNK; // short read means EOF reached
                byte[] ct = seal(key, salt, index, plain, 0, n, fin);
                writeInt(os, ct.length);
                os.write(fin ? FLAG_FINAL : 0);
                os.write(ct);
                index++;
                if (fin) {
                    break;
                }
            }
        }
    }

    private static void decryptFile(byte[] key, Path in, Path tmp)
            throws IOException, GeneralSecurityException, NotOursException, AuthException {
        byte[] header = new byte[MAGIC.length];
        try (InputStream is = Files.newInputStream(in, StandardOpenOption.READ);
             OutputStream os = new java.io.BufferedOutputStream(Files.newOutputStream(tmp,
                     StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING))) {
            int got = readUpTo(is, header);
            if (got < MAGIC.length) {
                throw new NotOursException("input is shorter than the 8-byte magic: not a filecrypt file");
            }
            if (!Arrays.equals(header, MAGIC)) {
                throw new NotOursException("bad magic: not a filecrypt file");
            }
            byte[] salt = new byte[SALT_LEN];
            readFullyOrAuth(is, salt, "truncated header (salt)");

            long index = 0;
            for (;;) {
                int len = readIntOrEof(is);
                if (len < 0) {
                    return;
                }
                if (len < TAG_LEN || len > CHUNK + TAG_LEN) {
                    throw new AuthException("corrupt chunk length: " + len);
                }
                int flag = is.read();
                if (flag < 0) {
                    throw new AuthException("truncated: missing chunk flags");
                }
                if ((flag & ~FLAG_FINAL) != 0) {
                    throw new AuthException("corrupt chunk flags: " + flag);
                }
                byte[] ct = new byte[len];
                readFullyOrAuth(is, ct, "truncated chunk");
                byte[] plain = open(key, salt, index, ct, (flag & FLAG_FINAL) != 0);
                os.write(plain);
                index++;
                if ((flag & FLAG_FINAL) != 0) {
                    return;
                }
            }
        }
    }

    // ---------------------------------------------------------------- crypto

    /** IV = salt (8 bytes) || big-endian chunk index (4 bytes): unique per chunk per encryption. */
    private static byte[] iv(byte[] salt, long index) {
        if (index < 0 || index > 0xFFFFFFFFL) {
            throw new IllegalStateException("chunk index overflow");
        }
        ByteBuffer bb = ByteBuffer.allocate(IV_LEN).order(ByteOrder.BIG_ENDIAN);
        bb.put(salt);
        bb.putInt(0);
        return bb.array();
    }

    /** AAD binds the final flag into the GCM tag. */
    private static byte[] aad(long index, boolean fin) {
        return new byte[]{(byte) (fin ? FLAG_FINAL : 0)};
    }

    private static byte[] seal(byte[] key, byte[] salt, long index, byte[] plain, int off, int len, boolean fin)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LEN * 8, iv(salt, index)));
        c.updateAAD(aad(index, fin));
        return c.doFinal(plain, off, len);
    }

    private static byte[] open(byte[] key, byte[] salt, long index, byte[] ct, boolean fin)
            throws AuthException, GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LEN * 8, iv(salt, index)));
        c.updateAAD(aad(index, fin));
        try {
            return c.doFinal(ct);
        } catch (AEADBadTagException e) {
            throw new AuthException("authentication failed: wrong key or tampered ciphertext");
        }
    }

    // ----------------------------------------------------------------- files

    private static byte[] readKey(Path keyPath) throws UsageException, IOException {
        if (!Files.isRegularFile(keyPath)) {
            throw new UsageException("key file not found or not a regular file: " + keyPath);
        }
        long size;
        try {
            size = Files.size(keyPath);
        } catch (IOException e) {
            throw new UsageException("cannot stat key file: " + keyPath);
        }
        if (size != KEY_LEN) {
            throw new UsageException("key must be exactly " + KEY_LEN + " raw bytes, got " + size);
        }
        try {
            return Files.readAllBytes(keyPath);
        } catch (IOException e) {
            throw new UsageException("cannot read key file: " + keyPath);
        }
    }

    private static void checkInput(Path in) throws UsageException {
        if (!Files.isRegularFile(in)) {
            throw new UsageException("input not found or not a regular file: " + in);
        }
        if (!Files.isReadable(in)) {
            throw new UsageException("input not readable: " + in);
        }
    }

    private static void checkOutput(Path in, Path out, boolean force) throws UsageException, IOException {
        Path absIn = in.toAbsolutePath().normalize();
        Path absOut = out.toAbsolutePath().normalize();
        if (absIn.equals(absOut)) {
            throw new UsageException("input and output must not be the same path");
        }
        try {
            if (Files.isSameFile(in, out)) {
                throw new UsageException("input and output refer to the same file");
            }
        } catch (IOException e) {
            // out does not exist yet: fine
        }
        if (Files.exists(out) && !force) {
            throw new UsageException("output already exists (use --force to overwrite): " + out);
        }
        checkParentDir(out);
    }

    private static void checkParentDir(Path out) throws UsageException {
        Path parent = out.toAbsolutePath().normalize().getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new UsageException("output directory does not exist: " + out);
        }
    }

    private static Path parentOrCwd(Path out) {
        Path parent = out.toAbsolutePath().normalize().getParent();
        return parent != null ? parent : Path.of(".");
    }

    private static void moveIntoPlace(Path tmp, Path out, boolean replace) throws IOException, UsageException {
        try {
            if (replace) {
                try {
                    Files.move(tmp, out, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, out, StandardCopyOption.REPLACE_EXISTING);
                }
            } else {
                try {
                    Files.move(tmp, out, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, out);
                }
            }
        } catch (FileAlreadyExistsException e) {
            throw new UsageException("output already exists (use --force to overwrite): " + out);
        }
    }

    private static void deleteQuietly(Path p) {
        if (p != null) {
            try {
                Files.deleteIfExists(p);
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    // ------------------------------------------------------------------- io

    /** Reads up to buf.length bytes; returns count, or -1 if EOF before any byte. */
    private static int readUpTo(InputStream is, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = is.read(buf, off, buf.length - off);
            if (n < 0) {
                return off == 0 ? -1 : off;
            }
            off += n;
        }
        return off;
    }

    private static void readFullyOrAuth(InputStream is, byte[] buf, String what)
            throws IOException, AuthException {
        if (readUpTo(is, buf) < buf.length) {
            throw new AuthException("truncated: " + what);
        }
    }

    /** Reads a big-endian int; returns -1 if EOF before the first byte, throws on partial. */
    private static int readIntOrEof(InputStream is) throws IOException, AuthException {
        byte[] b = new byte[4];
        int first = is.read();
        if (first < 0) {
            return -1;
        }
        b[0] = (byte) first;
        for (int i = 1; i < 4; i++) {
            int v = is.read();
            if (v < 0) {
                throw new AuthException("truncated: partial chunk length");
            }
            b[i] = (byte) v;
        }
        return ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN).getInt();
    }

    private static void writeInt(OutputStream os, int v) throws IOException {
        os.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(v).array());
    }

    // -------------------------------------------------------------- helpers

    private static String requireValue(String[] args, int i, String flag) throws UsageException {
        if (i >= args.length) {
            throw new UsageException("missing value for " + flag);
        }
        return args[i];
    }

    private static void err(String msg) {
        System.err.println("fcrypt: " + msg);
    }

    static final class UsageException extends Exception {
        UsageException(String msg) { super(msg); }
    }

    static final class AuthException extends Exception {
        AuthException(String msg) { super(msg); }
    }

    static final class NotOursException extends Exception {
        NotOursException(String msg) { super(msg); }
    }
}
