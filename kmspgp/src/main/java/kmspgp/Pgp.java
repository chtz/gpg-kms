package kmspgp;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;

final class Pgp {
    private Pgp() {}

    record SignatureMaterial(byte[] der, byte[] fingerprint) {}

    @FunctionalInterface
    interface DigestSigner {
        byte[] sign(byte[] digest) throws Exception;
    }

    @FunctionalInterface
    interface DocumentSigner {
        SignatureMaterial sign(byte[] digest) throws Exception;
    }

    static DigestSigner kmsSigner(KmsClient kms, String keyId) {
        return digest -> kms.sign(SignRequest.builder()
                .keyId(keyId)
                .message(SdkBytes.fromByteArray(digest))
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .build()).signature().asByteArray();
    }

    static DocumentSigner kmsDocumentSigner(KmsClient kms, String keyId, byte[] fingerprint) {
        var inner = kmsSigner(kms, keyId);
        return digest -> new SignatureMaterial(inner.sign(digest), fingerprint);
    }

    static byte[] fingerprint(Instant createdAt, byte[] spkiDer) throws Exception {
        return publicKey(createdAt, spkiDer).getFingerprint();
    }

    static String export(String user, Instant keyCreated, byte[] spki, DigestSigner signer)
            throws Exception {
        var pub = publicKey(keyCreated, spki);
        var hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(false, Date.from(keyCreated));
        hashed.addSignerUserID(false, user.getBytes(StandardCharsets.UTF_8));
        hashed.setIssuerFingerprint(false, pub);
        hashed.setKeyFlags(false, 0x03);
        var signature = signPgp(0x10, pub, MessageDigest.getInstance("SHA-256"), hashed, signer, gen ->
                gen.generateCertification(user, pub));
        return armor(out -> {
            pub.encode(out);
            new UserIDPacket(user).encode(out);
            signature.encode(out);
        });
    }

    static String sign(Instant hashedAt, MessageDigest fileDigest, DocumentSigner signer)
            throws Exception {
        var hashedGen = new PGPSignatureSubpacketGenerator();
        hashedGen.setSignatureCreationTime(false, Date.from(hashedAt));
        var hashedPackets = hashedGen.generate().toArray();
        byte[] hashedSubs = encodeSubpackets(hashedPackets);
        var prefix = new ByteArrayOutputStream(6 + hashedSubs.length);
        prefix.write(4);
        prefix.write(0x00);
        prefix.write(PublicKeyAlgorithmTags.ECDSA);
        prefix.write(HashAlgorithmTags.SHA256);
        prefix.write((hashedSubs.length >> 8) & 0xff);
        prefix.write(hashedSubs.length & 0xff);
        prefix.write(hashedSubs);
        byte[] hashedPrefix = prefix.toByteArray();

        fileDigest.update(hashedPrefix);
        fileDigest.update((byte) 0x04);
        fileDigest.update((byte) 0xff);
        writeUint32(fileDigest, hashedPrefix.length);
        byte[] digest = fileDigest.digest();

        System.err.println("OpenPGP SHA-256 digest (KMS signs this, not sha256sum of the file):");
        System.err.println("  digest:   " + HexFormat.of().formatHex(digest));
        System.err.println("  hashedAt: " + hashedAt.getEpochSecond() + " (" + hashedAt + ")");

        var material = signer.sign(digest);
        if (material.fingerprint() == null || material.fingerprint().length != 20) {
            throw new IllegalArgumentException("OpenPGP v4 fingerprint must be 20 bytes");
        }
        if (material.der() == null || material.der().length == 0) {
            throw new IllegalStateException("missing signature");
        }
        return encodeDocumentSignature(hashedPackets, digest, material);
    }

    static PGPPublicKey publicKey(Instant createdAt, byte[] spkiDer) throws Exception {
        var ec = (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(spkiDer));
        var point = uncompressedPoint(ec);
        var bcpgKey = new ECDSAPublicBCPGKey(SECObjectIdentifiers.secp256r1, new BigInteger(1, point));
        return new PGPPublicKey(
                new PublicKeyPacket(
                        PublicKeyPacket.VERSION_4,
                        PublicKeyAlgorithmTags.ECDSA,
                        Date.from(createdAt),
                        bcpgKey),
                new BcKeyFingerprintCalculator());
    }

    private static String encodeDocumentSignature(
            SignatureSubpacket[] hashedPackets,
            byte[] digest,
            SignatureMaterial material
    ) throws Exception {
        var unhashedGen = new PGPSignatureSubpacketGenerator();
        unhashedGen.setIssuerKeyID(false, keyId(material.fingerprint()));
        var rAndS = parseEcdsaDer(material.der());
        var packet = new SignaturePacket(
                SignaturePacket.VERSION_4,
                0x00,
                keyId(material.fingerprint()),
                PublicKeyAlgorithmTags.ECDSA,
                HashAlgorithmTags.SHA256,
                hashedPackets,
                unhashedGen.generate().toArray(),
                Arrays.copyOf(digest, 2),
                new MPInteger[] { new MPInteger(rAndS[0]), new MPInteger(rAndS[1]) });
        return armor(packet::encode);
    }

    private static byte[] encodeSubpackets(SignatureSubpacket[] packets)
            throws IOException {
        var out = new ByteArrayOutputStream();
        for (var packet : packets) {
            packet.encode(out);
        }
        return out.toByteArray();
    }

    private static long keyId(byte[] fingerprint) {
        long id = 0;
        for (int i = 12; i < 20; i++) {
            id = (id << 8) | (fingerprint[i] & 0xff);
        }
        return id;
    }

    private static BigInteger[] parseEcdsaDer(byte[] der) {
        var seq = ASN1Sequence.getInstance(der);
        return new BigInteger[] {
            ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(),
            ASN1Integer.getInstance(seq.getObjectAt(1)).getValue()
        };
    }

    private static void writeUint32(MessageDigest digest, int n) {
        digest.update((byte) ((n >>> 24) & 0xff));
        digest.update((byte) ((n >>> 16) & 0xff));
        digest.update((byte) ((n >>> 8) & 0xff));
        digest.update((byte) (n & 0xff));
    }

    private static byte[] uncompressedPoint(ECPublicKey key) {
        var w = key.getW();
        var point = new byte[65];
        point[0] = 0x04;
        toFixed(w.getAffineX(), point, 1);
        toFixed(w.getAffineY(), point, 33);
        return point;
    }

    private static void toFixed(BigInteger value, byte[] dest, int offset) {
        var raw = value.toByteArray();
        int src = Math.max(0, raw.length - 32);
        int dst = offset + 32 - (raw.length - src);
        System.arraycopy(raw, src, dest, dst, raw.length - src);
    }

    private static PGPSignature signPgp(
            int signatureType,
            PGPPublicKey pub,
            MessageDigest digest,
            PGPSignatureSubpacketGenerator hashed,
            DigestSigner signer,
            SignatureFn generate
    ) throws Exception {
        PGPContentSignerBuilder contentSigner = (keyAlgorithm, hashAlgorithm) -> new PGPContentSigner() {
            private final OutputStream digestStream = new DigestStream(digest);
            private byte[] digestValue;
            private byte[] signatureValue;

            @Override
            public OutputStream getOutputStream() {
                return digestStream;
            }

            @Override
            public byte[] getSignature() {
                if (signatureValue == null) {
                    try {
                        signatureValue = signer.sign(getDigest());
                    } catch (RuntimeException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                }
                return signatureValue;
            }

            @Override
            public byte[] getDigest() {
                if (digestValue == null) {
                    digestValue = digest.digest();
                }
                return digestValue;
            }

            @Override
            public int getType() {
                return signatureType;
            }

            @Override
            public int getHashAlgorithm() {
                return HashAlgorithmTags.SHA256;
            }

            @Override
            public int getKeyAlgorithm() {
                return pub.getAlgorithm();
            }

            @Override
            public long getKeyID() {
                return pub.getKeyID();
            }
        };

        var generator = new PGPSignatureGenerator(contentSigner, pub);
        generator.setHashedSubpackets(hashed.generate());
        generator.init(signatureType, new PGPPrivateKey(pub.getKeyID(), pub.getPublicKeyPacket(), null));
        return generate.apply(generator);
    }

    private static String armor(Encoder encoder) {
        var bytes = new ByteArrayOutputStream();
        try (var armored = ArmoredOutputStream.builder().clearHeaders().setVersion("kmspgp").build(bytes);
             var bcpg = new BCPGOutputStream(armored)) {
            encoder.encode(bcpg);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    static final class DigestStream extends OutputStream {
        private final MessageDigest digest;

        DigestStream(MessageDigest digest) {
            this.digest = digest;
        }

        @Override
        public void write(int b) {
            digest.update((byte) b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            digest.update(b, off, len);
        }
    }

    @FunctionalInterface
    private interface SignatureFn {
        PGPSignature apply(PGPSignatureGenerator generator) throws Exception;
    }

    @FunctionalInterface
    private interface Encoder {
        void encode(BCPGOutputStream out) throws IOException;
    }
}
