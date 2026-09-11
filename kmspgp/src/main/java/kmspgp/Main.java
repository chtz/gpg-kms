package kmspgp;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

public final class Main {
    private static final String USAGE =
            "usage: export --user-name NAME --user-email EMAIL KEY | -bsau KEY"
                    + " | lambda-export --api URL"
                    + " | lambda-sign --function NAME --api URL"
                    + " [--artifact NAME] [--version VER] [--environment ENV]";
    private static final int LAMBDA_POLL_INTERVAL_SECONDS = 2;
    private static final int LAMBDA_POLL_TIMEOUT_SECONDS = 1800;

    public static void main(String[] args) throws Exception {
        if (args.length >= 1 && "-bsau".equals(args[0])) {
            if (args.length != 2) {
                fail("usage: -bsau KEY");
            }
            sign(args[1]);
        } else if (args.length >= 1 && "export".equals(args[0])) {
            export(parseExport(args));
        } else if (args.length >= 1 && "lambda-export".equals(args[0])) {
            lambdaExport(parseLambdaExport(args));
        } else if (args.length >= 1 && "lambda-sign".equals(args[0])) {
            lambdaSign(parseLambdaSign(args));
        } else {
            fail(USAGE);
        }
    }

    private static void export(ExportArgs opts) throws Exception {
        try (var kms = kms()) {
            var key = load(kms, opts.keyId);
            var user = userId(opts.userName, opts.userEmail, key.des.keyMetadata().description());
            var created = key.des.keyMetadata().creationDate();
            System.out.println(Pgp.export(
                    user,
                    created,
                    key.pub.publicKey().asByteArray(),
                    Pgp.kmsSigner(kms, key.des.keyMetadata().keyId())));
        }
    }

    private static void sign(String keyId) throws Exception {
        try (var kms = kms()) {
            var key = load(kms, keyId);
            var digest = MessageDigest.getInstance("SHA-256");
            System.in.transferTo(new Pgp.DigestStream(digest));
            var pub = Pgp.publicKey(key.des.keyMetadata().creationDate(), key.pub.publicKey().asByteArray());
            System.out.println(Pgp.sign(
                    Instant.now(),
                    digest,
                    pub,
                    Pgp.kmsSigner(kms, key.des.keyMetadata().keyId())));
        }
    }

    private static void lambdaExport(LambdaExportArgs opts) throws Exception {
        System.out.println(LambdaSigning.fetchOpenPgpPublicKey(opts.api));
    }

    private static void lambdaSign(LambdaSignArgs opts) throws Exception {
        var remote = LambdaSigning.fetchPublicKey(opts.api);
        if (remote.keySpec() != null && !"ECC_NIST_P256".equals(remote.keySpec())) {
            throw new IllegalArgumentException("Only ECC_NIST_P256 is supported, got " + remote.keySpec());
        }
        var pub = Pgp.publicKey(remote.createdAt(), remote.spki());

        var fileSha = MessageDigest.getInstance("SHA-256");
        var openPgp = MessageDigest.getInstance("SHA-256");
        System.in.transferTo(new Pgp.TeeStream(new Pgp.DigestStream(fileSha), new Pgp.DigestStream(openPgp)));
        var fileSha256 = HexFormat.of().formatHex(fileSha.digest());

        var artifact = opts.artifact != null ? opts.artifact : "stdin";
        System.out.println(Pgp.sign(Instant.now(), openPgp, pub, digest ->
                LambdaSigning.signDigest(
                        opts.functionName,
                        digest,
                        fileSha256,
                        artifact,
                        opts.version,
                        opts.environment,
                        LAMBDA_POLL_INTERVAL_SECONDS,
                        LAMBDA_POLL_TIMEOUT_SECONDS)));
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

    private static LambdaExportArgs parseLambdaExport(String[] args) {
        String api = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--api" -> api = requireValue(args, ++i, "--api");
                default -> fail("usage: lambda-export --api URL");
            }
        }
        if (api == null) {
            fail("usage: lambda-export --api URL");
        }
        return new LambdaExportArgs(api);
    }

    private static LambdaSignArgs parseLambdaSign(String[] args) {
        String functionName = null;
        String api = null;
        String artifact = null;
        String version = null;
        String environment = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--function" -> functionName = requireValue(args, ++i, "--function");
                case "--api" -> api = requireValue(args, ++i, "--api");
                case "--artifact" -> artifact = requireValue(args, ++i, "--artifact");
                case "--version" -> version = requireValue(args, ++i, "--version");
                case "--environment" -> environment = requireValue(args, ++i, "--environment");
                default -> fail("usage: lambda-sign --function NAME --api URL"
                        + " [--artifact NAME] [--version VER] [--environment ENV]");
            }
        }
        if (functionName == null || api == null) {
            fail("usage: lambda-sign --function NAME --api URL"
                    + " [--artifact NAME] [--version VER] [--environment ENV]");
        }
        return new LambdaSignArgs(functionName, api, artifact, version, environment);
    }

    private static String userId(String userName, String userEmail, String description) {
        var user = userName + " <" + userEmail + ">";
        if (description != null && !description.isBlank()) {
            user += " (" + description.trim() + ")";
        }
        return user;
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

    private record LambdaExportArgs(String api) {}

    private record LambdaSignArgs(
            String functionName,
            String api,
            String artifact,
            String version,
            String environment
    ) {}

    private record Key(
            software.amazon.awssdk.services.kms.model.DescribeKeyResponse des,
            software.amazon.awssdk.services.kms.model.GetPublicKeyResponse pub
    ) {}
}
