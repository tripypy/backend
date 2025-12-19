package com.ssafy.jjtrip.domain.search.service;

import com.ssafy.jjtrip.domain.search.dto.TripSearchDoc;
import com.ssafy.jjtrip.domain.search.util.SearchUtil;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.data.elasticsearch.core.query.Query;
import org.springframework.data.elasticsearch.core.query.StringQuery;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
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
        """.formatted(SearchUtil.escapeJson(keyword), SearchUtil.escapeJson(keyword));

        Query query = new StringQuery(queryString);
        SearchHits<TripSearchDoc> searchHits = elasticsearchOperations.search(query, TripSearchDoc.class);

        return searchHits.stream()
                .map(SearchHit::getContent)
                .map(this::normalizeDoc) // Normalize mixed date formats
                .collect(Collectors.toList());
    }

    private TripSearchDoc normalizeDoc(TripSearchDoc doc) { // Redefining for correctness
          return new TripSearchDoc(
                doc.tripId(),
                doc.userId(),
                doc.title(),
                doc.locationSummary(),
                SearchUtil.normalizeDate(doc.startDate(), false),
                SearchUtil.normalizeDate(doc.endDate(), false),
                SearchUtil.normalizeDate(doc.createdAt(), true),
                doc.spotNames(),
                doc.spotCategories(),
                doc.spotsPreview()
        );
    }

    public void saveTrip(Trip trip, List<TripItem> items) {
        if (trip.getVisibility() != TripVisibility.PUBLIC) {
            deleteTrip(trip.getId());
            return;
        }

        List<String> spotNames = items.stream()
                .map(item -> item.getSpot().getName())
                .toList();

        List<String> spotCategories = items.stream()
                .map(item -> item.getSpot().getCategory())
                .toList();

        List<TripSearchDoc.SpotPreview> spotsPreview = items.stream()
                .map(item -> new TripSearchDoc.SpotPreview(
                        item.getSpot().getId(),
                        item.getSpot().getName(),
                        item.getSpot().getCategory()
                ))
                .toList();

        TripSearchDoc doc = new TripSearchDoc(
                trip.getId(),
                trip.getUserId(),
                trip.getTitle(),
                trip.getLocationSummary(),
                trip.getStartDate() != null ? trip.getStartDate().toString() : null,
                trip.getEndDate() != null ? trip.getEndDate().toString() : null,
                trip.getCreatedAt() != null ? trip.getCreatedAt().toString() : null,
                spotNames,
                spotCategories,
                spotsPreview
        );

        log.info("Saving trip to ES: {}", trip.getId());
        elasticsearchOperations.save(doc);
        log.info("Saved trip to ES: {}", trip.getId());
    }

    public void deleteTrip(Long tripId) {
        log.info("Deleting trip from ES: {}", tripId);
        elasticsearchOperations.delete(String.valueOf(tripId), TripSearchDoc.class);
        log.info("Deleted trip from ES: {}", tripId);
    }
}
