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
    private static final String EXPORT_ALIAS = "export";
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private LambdaSigning() {}

    static String exportPublicKey(String functionName) throws Exception {
        var payload = Map.of("action", "export");
        var json = invoke(qualifyExport(functionName), payload);
        if (!Json.bool(json, "ok")) {
            throw new IllegalStateException(message(json, "export failed"));
        }
        var armored = Json.str(json, "armored");
        if (armored == null || armored.isBlank()) {
            throw new IllegalStateException("export response missing armored");
        }
        return armored.stripTrailing();
    }

    static Pgp.SignatureMaterial signDigest(
            String functionName,
            byte[] digest,
            Instant hashedAt,
            String artifact,
            String version,
            String environment,
            int pollIntervalSeconds,
            int pollTimeoutSeconds
    ) throws Exception {
        var payload = new LinkedHashMap<String, Object>();
        payload.put("action", "create");
        payload.put("digest", HexFormat.of().formatHex(digest));
        payload.put("hashedAt", hashedAt.getEpochSecond());
        payload.put("artifact", artifact);
        payload.put("version", version);
        payload.put("environment", environment);

        var created = invoke(functionName, payload);
        if (!Json.bool(created, "ok")) {
            throw new IllegalStateException(message(created, "create failed"));
        }
        var pollUrl = Json.str(created, "pollUrl");
        var requestId = Json.str(created, "requestId");
        if (pollUrl == null || pollUrl.isBlank()) {
            throw new IllegalStateException("create response missing pollUrl");
        }
        System.err.println("Waiting for approval of request " + (requestId == null ? "?" : requestId));

        var waitStarted = Instant.now();
        var deadline = waitStarted.plusSeconds(pollTimeoutSeconds);
        var lastHeartbeat = Instant.EPOCH;
        String lastStatus = "";
        while (Instant.now().isBefore(deadline)) {
            var poll = Json.object(httpGet(pollUrl));
            if (!Json.bool(poll, "ok")) {
                throw new IllegalStateException(message(poll, "poll failed"));
            }
            var status = Json.str(poll, "status");
            var nextStatus = status == null ? "" : status;
            if (!nextStatus.equals(lastStatus)) {
                lastStatus = nextStatus;
                lastHeartbeat = Instant.now();
                System.err.println("Status: " + lastStatus);
            } else if ("WAITING".equals(lastStatus)
                    && Duration.between(lastHeartbeat, Instant.now()).toSeconds() >= 30) {
                lastHeartbeat = Instant.now();
                System.err.println(
                        "still waiting, " + Duration.between(waitStarted, Instant.now()).toSeconds() + "s");
            }
            switch (lastStatus) {
                case "SIGNED" -> {
                    var signature = Json.str(poll, "signature");
                    var fingerprint = Json.str(poll, "fingerprint");
                    if (signature == null || signature.isBlank()) {
                        throw new IllegalStateException("SIGNED response missing signature");
                    }
                    if (fingerprint == null || !fingerprint.matches("(?i)[0-9a-f]{40}")) {
                        throw new IllegalStateException("SIGNED response missing fingerprint");
                    }
                    return new Pgp.SignatureMaterial(
                            Base64.getDecoder().decode(signature),
                            HexFormat.of().parseHex(fingerprint));
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

    private static String qualifyExport(String functionName) {
        return functionName.endsWith(":" + EXPORT_ALIAS) ? functionName : functionName + ":" + EXPORT_ALIAS;
    }

    private static Map<String, Object> invoke(String functionName, Map<String, ?> payload)
            throws Exception {
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
        return Json.object(responseJson);
    }

    private static String httpGet(String url) throws Exception {
        var uri = URI.create(url);
        var request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " from "
                    + requestTarget(uri) + ": " + response.body());
        }
        return response.body();
    }

    private static String requestTarget(URI uri) {
        var host = uri.getHost() == null ? "" : uri.getHost();
        var path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        return host + path;
    }

    private static LambdaClient lambda() {
        return LambdaClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .region(DefaultAwsRegionProviderChain.builder().build().getRegion())
                .httpClient(UrlConnectionHttpClient.create())
                .build();
    }

    private static String message(Map<String, Object> json, String fallback) {
        var error = Json.str(json, "error");
        return error == null || error.isBlank() ? fallback : error;
    }
}
