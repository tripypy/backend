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
                .stream().map(SearchHit::getContent).toList();
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
