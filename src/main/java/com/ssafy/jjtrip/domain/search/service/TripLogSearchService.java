package com.ssafy.jjtrip.domain.search.service;

import com.ssafy.jjtrip.domain.search.dto.TripLogSearchDoc;
import com.ssafy.jjtrip.domain.search.util.SearchUtil;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;
import com.ssafy.jjtrip.domain.triplog.entity.TripLog;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.query.Query;
import org.springframework.data.elasticsearch.core.query.StringQuery;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
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
        """.formatted(SearchUtil.escapeJson(keyword), SearchUtil.escapeJson(keyword));

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
                SearchUtil.normalizeDate(doc.tripStartDate(), false),
                SearchUtil.normalizeDate(doc.tripEndDate(), false),
                SearchUtil.normalizeDate(doc.createdAt(), true),
                doc.imageUrls()
        );
    }

    public void saveTripLog(TripLog tripLog, Trip trip, List<String> imageUrls) {
        if (tripLog.getVisibility() != TripLogVisibility.PUBLIC ||
            trip.getVisibility() != TripVisibility.PUBLIC) {
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
}
