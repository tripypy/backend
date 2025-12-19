package com.ssafy.jjtrip.domain.search.util;

public class SearchUtil {

    private SearchUtil() {}

    public static String normalizeDate(String value, boolean isDateTime) {
        if (value == null) return null;
        if (value.matches("^\\d+$")) {
            try {
                long millis = Long.parseLong(value);
                java.time.ZonedDateTime zdt = java.time.Instant.ofEpochMilli(millis)
                        .atZone(java.time.ZoneId.systemDefault());
                if (isDateTime) {
                    return zdt.toLocalDateTime().toString();
                } else {
                    return zdt.toLocalDate().toString();
                }
            } catch (Exception e) {
                return value;
            }
        }
        return value;
    }

    public static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
