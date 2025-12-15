package com.ssafy.jjtrip.domain.search.service;

import com.ssafy.jjtrip.domain.search.dto.SpotSearchDoc;
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
public class SpotSearchService {

    private final ElasticsearchOperations elasticsearchOperations;

    public List<SpotSearchDoc> search(String keyword) {
        String[] searchFields = {"name", "address", "category"};

        String queryString = """
        {
          "multi_match": {
            "query": "%s",
            "fields": ["%s"]
          }
        }
        """.formatted(keyword, String.join("\", \"", searchFields));

        Query query = new StringQuery(queryString);
        SearchHits<SpotSearchDoc> searchHits = elasticsearchOperations.search(query, SpotSearchDoc.class);

        return searchHits.stream()
                .map(SearchHit::getContent)
                .collect(Collectors.toList());
    }
}
