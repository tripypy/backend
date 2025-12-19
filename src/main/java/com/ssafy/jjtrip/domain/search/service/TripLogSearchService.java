package com.ssafy.jjtrip.domain.search.service;

import com.ssafy.jjtrip.domain.search.dto.TripLogSearchDoc;
import lombok.RequiredArgsConstructor;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.query.Query;
import org.springframework.data.elasticsearch.core.query.StringQuery;
import org.springframework.stereotype.Service;
import java.util.List;

@RequiredArgsConstructor
@Service
@lombok.extern.slf4j.Slf4j
public class TripLogSearchService {

    private final ElasticsearchOperations elasticsearchOperations;

    public List<TripLogSearchDoc> search(String keyword) {
        String queryString = """
        {
          "bool": {
            "must": [
              {
                "multi_match": {
                  "query": "%s",
                  "fields": [
                    "title^5",
                    "content^4",
                    "trip_location_summary^3"
                  ],
                  "operator": "and",
                  "type": "best_fields"
                }
              }
            ],
            "should": [
              {
                "multi_match": {
                  "query": "%s",
                  "fields": [
                    "title.ngram^0.6",
                    "content.ngram^0.5",
                    "trip_location_summary.ngram^0.3"
                  ],
                  "type": "best_fields"
                }
              }
            ],
            "minimum_should_match": 0
          }
        }
        """.formatted(escapeJson(keyword), escapeJson(keyword));

        Query query = new StringQuery(queryString);
        return elasticsearchOperations.search(query, TripLogSearchDoc.class)
                .stream()
                .map(SearchHit::getContent)
                .map(this::normalizeDoc)
                .toList();
    }

    private TripLogSearchDoc normalizeDoc(TripLogSearchDoc doc) {
        return new TripLogSearchDoc(
                doc.logId(),
                doc.tripId(),
                doc.userId(),
                doc.title(),
                doc.content(),
                doc.tripLocationSummary(),
                normalizeDate(doc.tripStartDate(), false),
                normalizeDate(doc.tripEndDate(), false),
                normalizeDate(doc.createdAt(), true),
                doc.imageUrls()
        );
    }

    private String normalizeDate(String value, boolean isDateTime) {
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

    public void saveTripLog(com.ssafy.jjtrip.domain.triplog.entity.TripLog tripLog, com.ssafy.jjtrip.domain.trip.entity.Trip trip, List<String> imageUrls) {
        if (tripLog.getVisibility() != com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility.PUBLIC ||
            trip.getVisibility() != com.ssafy.jjtrip.domain.trip.entity.TripVisibility.PUBLIC) {
            deleteTripLog(tripLog.getId());
            return;
        }

        TripLogSearchDoc doc = new TripLogSearchDoc(
                tripLog.getId(),
                trip.getId(),
                trip.getUserId(),
                tripLog.getTitle(),
                tripLog.getContent(),
                trip.getLocationSummary(),
                trip.getStartDate() != null ? trip.getStartDate().toString() : null,
                trip.getEndDate() != null ? trip.getEndDate().toString() : null,
                tripLog.getCreatedAt() != null ? tripLog.getCreatedAt().toString() : null,
                imageUrls
        );

        log.info("Saving trip log to ES: {}", tripLog.getId());
        elasticsearchOperations.save(doc);
        log.info("Saved trip log to ES: {}", tripLog.getId());
    }

    public void deleteTripLog(Long logId) {
        log.info("Deleting trip log from ES: {}", logId);
        elasticsearchOperations.delete(String.valueOf(logId), TripLogSearchDoc.class);
        log.info("Deleted trip log from ES: {}", logId);
    }

    private static String escapeJson(String s) {
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
