package kmspgp;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
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
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

final class Pgp {
    private Pgp() {}

    static String export(String user, DescribeKeyResponse des, GetPublicKeyResponse pubRes, KmsClient kms)
            throws Exception {
        var pub = publicKey(des, pubRes);
        var hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(false, Date.from(des.keyMetadata().creationDate()));
        hashed.addSignerUserID(false, user.getBytes(StandardCharsets.UTF_8));
        hashed.setIssuerFingerprint(false, pub);
        hashed.setKeyFlags(false, 0x03);
        var signature = signPgp(0x10, pub, MessageDigest.getInstance("SHA-256"), hashed, kms, des, gen ->
                gen.generateCertification(user, pub));
        return armor(out -> {
            pub.encode(out);
            new UserIDPacket(user).encode(out);
            signature.encode(out);
        });
    }

    static String sign(
            Instant now,
            MessageDigest digest,
            DescribeKeyResponse des,
            GetPublicKeyResponse pubRes,
            KmsClient kms
    ) throws Exception {
        var pub = publicKey(des, pubRes);
        var hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(false, Date.from(now));
        var signature = signPgp(0x00, pub, digest, hashed, kms, des, PGPSignatureGenerator::generate);
        return armor(out -> signature.encode(out));
    }

    private static PGPPublicKey publicKey(DescribeKeyResponse des, GetPublicKeyResponse pubRes) throws Exception {
        var ec = (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(pubRes.publicKey().asByteArray()));
        var point = uncompressedPoint(ec);
        var bcpgKey = new ECDSAPublicBCPGKey(SECObjectIdentifiers.secp256r1, new BigInteger(1, point));
        return new PGPPublicKey(
                new PublicKeyPacket(
                        PublicKeyPacket.VERSION_4,
                        PublicKeyAlgorithmTags.ECDSA,
                        Date.from(des.keyMetadata().creationDate()),
                        bcpgKey),
                new BcKeyFingerprintCalculator());
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
            KmsClient kms,
            DescribeKeyResponse des,
            SignatureFn generate
    ) throws Exception {
        PGPContentSignerBuilder signer = (keyAlgorithm, hashAlgorithm) -> new PGPContentSigner() {
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
                    signatureValue = kms.sign(SignRequest.builder()
                            .keyId(des.keyMetadata().keyId())
                            .message(SdkBytes.fromByteArray(getDigest()))
                            .messageType(MessageType.DIGEST)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build()).signature().asByteArray();
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

        var generator = new PGPSignatureGenerator(signer, pub);
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
