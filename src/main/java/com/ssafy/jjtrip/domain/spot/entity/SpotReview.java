package com.ssafy.jjtrip.domain.spot.entity;

import com.ssafy.jjtrip.common.entity.BaseEntityWithUpdate;
import java.math.BigDecimal;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class SpotReview extends BaseEntityWithUpdate {
    private Long spotId;
    private Long userId; // Assuming we use ID reference or User object. Let's use ID for simplicity in MyBatis often, but object for JPA.
                         // But the project uses MyBatis? `SpotMapper` suggests MyBatis.
                         // In MyBatis, usually we map fields matching DB columns.
                         // `trit-db-schema.sql` has `user_id` and `spot_id`.
                         // Let's check `Spot` entity again. It has `kakaoPlaceId` etc. It extends `BaseEntity`.
                         // `Spot` does not seem to have `User` (it's not user specific).
                         // Let's check `Trip` or `TripLog` entity if available to see how they handle relations.
                         // I'll assume for now simple fields matching DB columns.
    
    private BigDecimal rating;
    private String content;
    
    // For joining User info in Mapper, we might need a `User` field or `writer` field in DTO. 
    // In Entity, let's keep it simple mapping to Table. 
    // If I want to fetch User info, I'll extend this or use a separate DTO.
    // However, usually Entity reflects the Table.
}
