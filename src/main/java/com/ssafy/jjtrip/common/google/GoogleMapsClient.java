package com.ssafy.jjtrip.common.google;

import com.ssafy.jjtrip.common.google.dto.GoogleMapsDto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.math.BigDecimal;
import java.util.Collections;

@Component
@RequiredArgsConstructor
@Slf4j
public class GoogleMapsClient {

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${google.maps.api-key}")
    private String apiKey;

    private static final String SEARCH_URL = "https://places.googleapis.com/v1/places:searchText";
    private static final String MEDIA_URL_TEMPLATE = "https://places.googleapis.com/v1/%s/media?key=%s&skipHttpRedirect=true&maxHeightPx=400&maxWidthPx=400";

    public Place searchPlace(String name, BigDecimal lat, BigDecimal lng) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-Goog-Api-Key", apiKey);
            headers.set("X-Goog-FieldMask", "places.name,places.photos");

            SearchPlaceRequest request = new SearchPlaceRequest(
                    name,
                    "ko",
                    LocationBias.of(lat, lng, 500.0) // 500m radius bias
            );

            HttpEntity<SearchPlaceRequest> entity = new HttpEntity<>(request, headers);

            ResponseEntity<SearchPlaceResponse> response = restTemplate.exchange(
                    SEARCH_URL,
                    HttpMethod.POST,
                    entity,
                    SearchPlaceResponse.class
            );

            if (response.getBody() != null && response.getBody().places() != null && !response.getBody().places().isEmpty()) {
                return response.getBody().places().get(0);
            }
        } catch (Exception e) {
            log.error("Google Maps Places Search failed: {}", e.getMessage());
        }
        return null;
    }

    public byte[] fetchPhoto(String photoResourceName) {
        try {
            // 1. Get the actual download URL (since we use skipHttpRedirect=true for metadata if needed, but here we want bytes directly)
            // Actually, to get bytes directly we can just not use skipHttpRedirect or handle the redirect.
            // Google Places Photo API returns a 302 redirect to the image URL.
            // RestTemplate follows redirects by default usually, but let's check the API spec.
            // "If you skip the redirect... the response contains a JSON object with a name and photoUri."
            // We want the actual image bytes. So we should NOT skip redirect, OR we fetch the URI and download.
            // Let's try downloading directly.

            String url = String.format("https://places.googleapis.com/v1/%s/media?key=%s&maxHeightPx=800&maxWidthPx=800", photoResourceName, apiKey);
            
            return restTemplate.getForObject(url, byte[].class);

        } catch (Exception e) {
            log.error("Failed to fetch photo from Google Maps: {}", e.getMessage());
            return null;
        }
    }
}
