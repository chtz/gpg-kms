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
                    + " | lambda-export --user-name NAME --user-email EMAIL"
                    + " | lambda-sign [--artifact NAME] [--version VER] [--environment ENV]";

    public static void main(String[] args) throws Exception {
        if (args.length >= 2 && "-bsau".equals(args[0])) {
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
        var api = requireEnv("KMSPGP_LAMBDA_API_BASE_URL");
        System.out.println(LambdaSigning.fetchOpenPgpPublicKey(api, opts.userName, opts.userEmail));
    }

    private static void lambdaSign(LambdaSignArgs opts) throws Exception {
        var api = requireEnv("KMSPGP_LAMBDA_API_BASE_URL");
        var functionName = requireEnv("KMSPGP_LAMBDA_FUNCTION_NAME");
        var interval = envInt("KMSPGP_LAMBDA_POLL_INTERVAL_SECONDS", 2);
        var timeout = envInt("KMSPGP_LAMBDA_POLL_TIMEOUT_SECONDS", 1800);

        var remote = LambdaSigning.fetchPublicKey(api);
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
                        functionName,
                        digest,
                        fileSha256,
                        artifact,
                        opts.version,
                        opts.environment,
                        interval,
                        timeout)));
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
        String userName = null;
        String userEmail = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--user-name" -> userName = requireValue(args, ++i, "--user-name");
                case "--user-email" -> userEmail = requireValue(args, ++i, "--user-email");
                default -> fail("usage: lambda-export --user-name NAME --user-email EMAIL");
            }
        }
        if (userName == null || userEmail == null) {
            fail("usage: lambda-export --user-name NAME --user-email EMAIL");
        }
        return new LambdaExportArgs(userName, userEmail);
    }

    private static LambdaSignArgs parseLambdaSign(String[] args) {
        String artifact = null;
        String version = null;
        String environment = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--artifact" -> artifact = requireValue(args, ++i, "--artifact");
                case "--version" -> version = requireValue(args, ++i, "--version");
                case "--environment" -> environment = requireValue(args, ++i, "--environment");
                default -> fail("usage: lambda-sign [--artifact NAME] [--version VER] [--environment ENV]");
            }
        }
        return new LambdaSignArgs(artifact, version, environment);
    }

    private static String userId(String userName, String userEmail, String description) {
        var user = userName + " <" + userEmail + ">";
        if (description != null && !description.isBlank()) {
            user += " (" + description.trim() + ")";
        }
        return user;
    }

    private static String requireEnv(String name) {
        var value = System.getenv(name);
        if (value == null || value.isBlank()) {
            fail(name + " is required");
        }
        return value;
    }

    private static int envInt(String name, int defaultValue) {
        var value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            var parsed = Integer.parseInt(value);
            if (parsed <= 0) {
                fail(name + " must be a positive integer");
            }
            return parsed;
        } catch (NumberFormatException e) {
            fail(name + " must be a positive integer");
            return defaultValue;
        }
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

    private record LambdaExportArgs(String userName, String userEmail) {}

    private record LambdaSignArgs(String artifact, String version, String environment) {}

    private record Key(
            software.amazon.awssdk.services.kms.model.DescribeKeyResponse des,
            software.amazon.awssdk.services.kms.model.GetPublicKeyResponse pub
    ) {}
}
