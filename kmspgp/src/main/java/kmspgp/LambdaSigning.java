package kmspgp;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

final class LambdaSigning {
    private LambdaSigning() {}

    record PublicKey(
            String pem,
            byte[] spki,
            String keySpec,
            Instant createdAt,
            String description
    ) {}

    static PublicKey fetchPublicKey(String apiBaseUrl) throws Exception {
        var body = httpGet(join(apiBaseUrl, "/public-key"));
        var json = Json.object(body);
        if (!Json.bool(json, "ok")) {
            throw new IllegalStateException(message(json, "public-key request failed"));
        }
        var pem = Json.str(json, "publicKeyPem");
        var spec = Json.str(json, "keySpec");
        var created = Json.str(json, "creationDate");
        if (pem == null || pem.isBlank()) {
            throw new IllegalStateException("public-key response missing publicKeyPem");
        }
        if (created == null || created.isBlank()) {
            throw new IllegalStateException("public-key response missing creationDate");
        }
        return new PublicKey(
                pem,
                pemToDer(pem),
                spec,
                Instant.parse(created),
                Json.str(json, "description"));
    }

    static String fetchOpenPgpPublicKey(String apiBaseUrl) throws Exception {
        var json = Json.object(httpGet(join(apiBaseUrl, "/openpgp-public-key")));
        if (!Json.bool(json, "ok")) {
            throw new IllegalStateException(message(json, "openpgp-public-key request failed"));
        }
        var armored = Json.str(json, "armored");
        if (armored == null || armored.isBlank()) {
            throw new IllegalStateException("openpgp-public-key response missing armored");
        }
        return armored.stripTrailing();
    }

    static byte[] signDigest(
            String functionName,
            byte[] digest,
            String fileSha256,
            String artifact,
            String version,
            String environment,
            int pollIntervalSeconds,
            int pollTimeoutSeconds
    ) throws Exception {
        var payload = new LinkedHashMap<String, Object>();
        payload.put("action", "create");
        payload.put("digest", HexFormat.of().formatHex(digest));
        payload.put("fileSha256", fileSha256);
        payload.put("artifact", artifact);
        payload.put("version", version);
        payload.put("environment", environment);
        payload.put("metadata", Map.of("format", "openpgp"));

        String responseJson;
        try (var lambda = lambda()) {
            var invoke = lambda.invoke(InvokeRequest.builder()
                    .functionName(functionName)
                    .payload(SdkBytes.fromUtf8String(Json.stringify(payload)))
                    .build());
            if (invoke.functionError() != null) {
                throw new IllegalStateException("Lambda error: " + invoke.functionError()
                        + " " + invoke.payload().asUtf8String());
            }
            responseJson = invoke.payload().asUtf8String();
        }
        var created = Json.object(responseJson);
        if (!Json.bool(created, "ok")) {
            throw new IllegalStateException(message(created, "create failed"));
        }
        var pollUrl = Json.str(created, "pollUrl");
        var requestId = Json.str(created, "requestId");
        if (pollUrl == null || pollUrl.isBlank()) {
            throw new IllegalStateException("create response missing pollUrl");
        }
        System.err.println("Waiting for approval of request " + (requestId == null ? "?" : requestId));
        System.err.println("Approve via the SNS link, then this command will continue.");

        var deadline = Instant.now().plusSeconds(pollTimeoutSeconds);
        String lastStatus = "";
        while (Instant.now().isBefore(deadline)) {
            var poll = Json.object(httpGet(pollUrl));
            if (!Json.bool(poll, "ok")) {
                throw new IllegalStateException(message(poll, "poll failed"));
            }
            var status = Json.str(poll, "status");
            lastStatus = status == null ? "" : status;
            System.err.println("Status: " + lastStatus);
            switch (lastStatus) {
                case "SIGNED" -> {
                    var signature = Json.str(poll, "signature");
                    if (signature == null || signature.isBlank()) {
                        throw new IllegalStateException("SIGNED response missing signature");
                    }
                    return Base64.getDecoder().decode(signature);
                }
                case "FAILED" -> throw new IllegalStateException(message(poll, "signing failed"));
                case "REJECTED" -> throw new IllegalStateException(
                        Json.str(poll, "rejectionReason") == null
                                ? "signing request rejected"
                                : Json.str(poll, "rejectionReason"));
                default -> Thread.sleep(Duration.ofSeconds(Math.max(1, pollIntervalSeconds)));
            }
        }
        throw new IllegalStateException(
                "Timed out after " + pollTimeoutSeconds + "s waiting for SIGNED (last status: "
                        + (lastStatus.isBlank() ? "unknown" : lastStatus) + ")");
    }

    static byte[] pemToDer(String pem) {
        var b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }

    private static String httpGet(String url) throws Exception {
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        var request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " from " + url + ": "
                    + response.body());
        }
        return response.body();
    }

    private static LambdaClient lambda() {
        return LambdaClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(DefaultAwsRegionProviderChain.builder().build().getRegion())
                .httpClient(UrlConnectionHttpClient.create())
                .build();
    }

    private static String join(String base, String path) {
        if (base.endsWith("/")) {
            return base.substring(0, base.length() - 1) + path;
        }
        return base + path;
    }

    private static String message(Map<String, Object> json, String fallback) {
        var error = Json.str(json, "error");
        return error == null || error.isBlank() ? fallback : error;
    }
}
