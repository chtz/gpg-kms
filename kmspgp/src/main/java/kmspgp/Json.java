package kmspgp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

final class Json {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    private static final TypeReference<Map<String, Object>> OBJECT = new TypeReference<>() {};

    private Json() {}

    static String stringify(Map<String, ?> obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static Map<String, Object> object(String json) {
        try {
            var value = MAPPER.readValue(json, OBJECT);
            if (value == null) {
                throw new IllegalArgumentException("JSON object expected");
            }
            return value;
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static String str(Map<String, Object> obj, String key) {
        var value = obj.get(key);
        return value == null ? null : value.toString();
    }

    static boolean bool(Map<String, Object> obj, String key) {
        var value = obj.get(key);
        return value instanceof Boolean b && b;
    }
}
