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
            "should": [
              {
                "multi_match": {
                  "query": "%s",
                  "fields": ["title^3", "content^2", "locationSummary^2"],
                  "operator": "and"
                }
              },
              {
                "nested": {
                  "path": "spots",
                  "query": {
                    "multi_match": {
                      "query": "%s",
                      "fields": ["spots.name^2", "spots.category^3", "spots.address"]
                    }
                  }
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
        """.formatted(escapeJson(keyword), escapeJson(keyword));

        Query query = new StringQuery(queryString);
        return elasticsearchOperations.search(query, TripLogSearchDoc.class)
                .stream().map(SearchHit::getContent).toList();
    }

    private static String escapeJson(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
