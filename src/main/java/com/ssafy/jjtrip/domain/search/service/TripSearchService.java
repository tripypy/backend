package com.ssafy.jjtrip.domain.search.service;

import com.ssafy.jjtrip.domain.search.dto.TripSearchDoc;
import lombok.RequiredArgsConstructor;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.data.elasticsearch.core.query.Query;
import org.springframework.data.elasticsearch.core.query.StringQuery;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class TripSearchService {

    private final ElasticsearchOperations elasticsearchOperations;

    public List<TripSearchDoc> search(String keyword) {
        String queryString = """
        {
          "bool": {
            "must": [
              {
                "multi_match": {
                  "query": "%s",
                  "fields": [
                    "title^5",
                    "location_summary^4",
                    "spot_names^3"
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
                    "location_summary.ngram^0.5",
                    "spot_names.ngram^0.3"
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
        SearchHits<TripSearchDoc> searchHits = elasticsearchOperations.search(query, TripSearchDoc.class);

        return searchHits.stream()
                .map(SearchHit::getContent)
                .collect(Collectors.toList());
    }

    private static String escapeJson(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
