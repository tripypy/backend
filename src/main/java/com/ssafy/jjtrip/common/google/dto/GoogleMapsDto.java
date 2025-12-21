package com.ssafy.jjtrip.common.google.dto;

import java.math.BigDecimal;
import java.util.List;

public class GoogleMapsDto {

    public record SearchPlaceRequest(
            String textQuery,
            String languageCode,
            LocationBias locationBias
    ) {}

    public record LocationBias(
            Circle circle
    ) {
        public static LocationBias of(BigDecimal lat, BigDecimal lng, double radius) {
            return new LocationBias(new Circle(new Center(lat, lng), radius));
        }
    }

    public record Circle(
            Center center,
            double radius
    ) {}

    public record Center(
            BigDecimal latitude,
            BigDecimal longitude
    ) {}

    public record SearchPlaceResponse(
            List<Place> places
    ) {}

    public record Place(
            String name,
            List<Photo> photos
    ) {}

    public record Photo(
            String name,
            Integer widthPx,
            Integer heightPx
    ) {}
}
