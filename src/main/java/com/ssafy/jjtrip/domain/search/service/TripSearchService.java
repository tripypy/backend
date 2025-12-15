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
        String[] searchFields = {"title"};

        String queryString = """
        {
          "multi_match": {
            "query": "%s",
            "fields": ["%s"]
          }
        }
        """.formatted(keyword, String.join("\", \"", searchFields));

        Query query = new StringQuery(queryString);
        SearchHits<TripSearchDoc> searchHits = elasticsearchOperations.search(query, TripSearchDoc.class);

        return searchHits.stream()
                .map(SearchHit::getContent)
                .collect(Collectors.toList());
    }
}
