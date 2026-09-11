package kmspgp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Json {
    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    static String stringify(Map<String, ?> obj) {
        var out = new StringBuilder();
        writeValue(out, obj);
        return out.toString();
    }

    static Map<String, Object> object(String json) {
        var parser = new Json(json);
        parser.skipWs();
        var value = parser.parseValue();
        parser.skipWs();
        if (!(value instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("JSON object expected");
        }
        @SuppressWarnings("unchecked")
        var typed = (Map<String, Object>) map;
        return typed;
    }

    static String str(Map<String, Object> obj, String key) {
        var value = obj.get(key);
        return value == null ? null : value.toString();
    }

    static boolean bool(Map<String, Object> obj, String key) {
        var value = obj.get(key);
        return value instanceof Boolean b && b;
    }

    private static void writeValue(StringBuilder out, Object value) {
        switch (value) {
            case null -> out.append("null");
            case String str -> writeString(out, str);
            case Boolean b -> out.append(b);
            case Number n -> out.append(n);
            case Map<?, ?> map -> {
                out.append('{');
                var first = true;
                for (var entry : map.entrySet()) {
                    if (entry.getValue() == null) {
                        continue;
                    }
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    writeString(out, String.valueOf(entry.getKey()));
                    out.append(':');
                    writeValue(out, entry.getValue());
                }
                out.append('}');
            }
            default -> throw new IllegalArgumentException("Cannot encode " + value.getClass());
        }
    }

    private static void writeString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private Object parseValue() {
        skipWs();
        if (i >= s.length()) {
            throw new IllegalArgumentException("Unexpected end of JSON");
        }
        return switch (s.charAt(i)) {
            case '{' -> parseObject();
            case '[' -> parseArray();
            case '"' -> parseString();
            case 't' -> parseLiteral("true", Boolean.TRUE);
            case 'f' -> parseLiteral("false", Boolean.FALSE);
            case 'n' -> parseLiteral("null", null);
            default -> parseNumber();
        };
    }

    private Map<String, Object> parseObject() {
        i++;
        var map = new LinkedHashMap<String, Object>();
        skipWs();
        if (peek('}')) {
            i++;
            return map;
        }
        while (true) {
            skipWs();
            var key = parseString();
            skipWs();
            expect(':');
            map.put(key, parseValue());
            skipWs();
            if (peek('}')) {
                i++;
                return map;
            }
            expect(',');
        }
    }

    private List<Object> parseArray() {
        i++;
        var list = new ArrayList<Object>();
        skipWs();
        if (peek(']')) {
            i++;
            return list;
        }
        while (true) {
            list.add(parseValue());
            skipWs();
            if (peek(']')) {
                i++;
                return list;
            }
            expect(',');
        }
    }

    private String parseString() {
        expect('"');
        var out = new StringBuilder();
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (i >= s.length()) {
                throw new IllegalArgumentException("Unterminated escape");
            }
            char e = s.charAt(i++);
            switch (e) {
                case '"', '\\', '/' -> out.append(e);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (i + 4 > s.length()) {
                        throw new IllegalArgumentException("Bad unicode escape");
                    }
                    out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                }
                default -> throw new IllegalArgumentException("Bad escape \\" + e);
            }
        }
        throw new IllegalArgumentException("Unterminated string");
    }

    private Object parseNumber() {
        int start = i;
        if (peek('-')) {
            i++;
        }
        while (i < s.length() && Character.isDigit(s.charAt(i))) {
            i++;
        }
        if (peek('.')) {
            i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) {
                i++;
            }
        }
        var raw = s.substring(start, i);
        if (raw.indexOf('.') >= 0) {
            return Double.parseDouble(raw);
        }
        return Long.parseLong(raw);
    }

    private Object parseLiteral(String literal, Object value) {
        if (!s.startsWith(literal, i)) {
            throw new IllegalArgumentException("Expected " + literal);
        }
        i += literal.length();
        return value;
    }

    private void skipWs() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
    }

    private boolean peek(char c) {
        return i < s.length() && s.charAt(i) == c;
    }

    private void expect(char c) {
        if (!peek(c)) {
            throw new IllegalArgumentException("Expected " + c);
        }
        i++;
    }
}
