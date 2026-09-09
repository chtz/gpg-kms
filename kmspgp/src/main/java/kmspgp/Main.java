package kmspgp;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;

import java.security.MessageDigest;
import java.time.Instant;

public final class Main {
    public static void main(String[] args) throws Exception {
        if (args.length >= 2 && "-bsau".equals(args[0])) {
            sign(args[1]);
        } else if (args.length >= 1 && "export".equals(args[0])) {
            export(parseExport(args));
        } else {
            fail("usage: export --user-name NAME --user-email EMAIL KEY | -bsau KEY");
        }
    }

    private static void export(ExportArgs opts) throws Exception {
        try (var kms = kms()) {
            var key = load(kms, opts.keyId);
            var user = opts.userName + " <" + opts.userEmail + ">";
            var description = key.des.keyMetadata().description();
            if (description != null && !description.isBlank()) {
                user += " (" + description.trim() + ")";
            }
            System.out.println(Pgp.export(user, key.des, key.pub, kms));
        }
    }

    private static void sign(String keyId) throws Exception {
        try (var kms = kms()) {
            var key = load(kms, keyId);
            var digest = MessageDigest.getInstance("SHA-256");
            System.in.transferTo(new Pgp.DigestStream(digest));
            System.out.println(Pgp.sign(Instant.now(), digest, key.des, key.pub, kms));
        }
    }

    private static Key load(KmsClient kms, String keyId) {
        var des = kms.describeKey(DescribeKeyRequest.builder().keyId(keyId).build());
        var pub = kms.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build());
        if (pub.keySpec() != KeySpec.ECC_NIST_P256) {
            throw new IllegalArgumentException("Only ECC_NIST_P256 is supported, got " + pub.keySpecAsString());
        }
        return new Key(des, pub);
    }

    private static KmsClient kms() {
        return KmsClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(DefaultAwsRegionProviderChain.builder().build().getRegion())
                .httpClient(UrlConnectionHttpClient.create())
                .build();
    }

    private static ExportArgs parseExport(String[] args) {
        String userName = null;
        String userEmail = null;
        String keyId = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--user-name" -> userName = requireValue(args, ++i, "--user-name");
                case "--user-email" -> userEmail = requireValue(args, ++i, "--user-email");
                default -> {
                    if (args[i].startsWith("-") || keyId != null) {
                        fail("usage: export --user-name NAME --user-email EMAIL KEY");
                    }
                    keyId = args[i];
                }
            }
        }
        if (userName == null || userEmail == null || keyId == null) {
            fail("usage: export --user-name NAME --user-email EMAIL KEY");
        }
        return new ExportArgs(userName, userEmail, keyId);
    }

    private static String requireValue(String[] args, int i, String option) {
        if (i >= args.length) {
            fail("missing value for " + option);
        }
        return args[i];
    }

    private static void fail(String message) {
        System.err.println(message);
        System.exit(1);
        throw new IllegalStateException(message);
    }

    private record ExportArgs(String userName, String userEmail, String keyId) {}

    private record Key(DescribeKeyResponse des, GetPublicKeyResponse pub) {}
}
