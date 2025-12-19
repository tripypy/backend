package com.ssafy.jjtrip.domain.spot.mapper;

import com.ssafy.jjtrip.domain.spot.dto.SpotReviewResponseDto;
import com.ssafy.jjtrip.domain.spot.entity.SpotReview;
import org.apache.ibatis.annotations.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Mapper
public interface SpotReviewMapper {

    @Insert("INSERT INTO spot_review (spot_id, user_id, rating, content) " +
            "VALUES (#{spotId}, #{userId}, #{rating}, #{content})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insert(SpotReview review);

    @Select("""
            <script>
            SELECT
                r.id,
                r.spot_id as spotId,
                r.user_id as userId,
                u.nickname as userNickname,
                u.profile_image_url as userProfileImage,
                r.rating,
                r.content,
                r.created_at as createdAt,
                r.updated_at as updatedAt
            FROM spot_review r
            JOIN user u ON r.user_id = u.id
            WHERE r.spot_id = #{spotId}
            ORDER BY r.created_at DESC
            </script>
            """)
    @ConstructorArgs({
            @Arg(column = "id", javaType = Long.class),
            @Arg(column = "spotId", javaType = Long.class),
            @Arg(column = "userId", javaType = Long.class),
            @Arg(column = "userNickname", javaType = String.class),
            @Arg(column = "userProfileImage", javaType = String.class),
            @Arg(column = "rating", javaType = BigDecimal.class),
            @Arg(column = "content", javaType = String.class),
            @Arg(column = "createdAt", javaType = LocalDateTime.class),
            @Arg(column = "updatedAt", javaType = LocalDateTime.class)
    })
    List<SpotReviewResponseDto> findBySpotId(Long spotId);

    @Select("SELECT * FROM spot_review WHERE id = #{id}")
    Optional<SpotReview> findById(Long id);

    @Update("UPDATE spot_review SET rating = #{rating}, content = #{content}, updated_at = NOW() WHERE id = #{id}")
    void update(SpotReview review);

    @Delete("DELETE FROM spot_review WHERE id = #{id}")
    void delete(Long id);

    @Select("SELECT COUNT(*) FROM spot_review WHERE spot_id = #{spotId}")
    int countBySpotId(Long spotId);

    @Select("SELECT COALESCE(AVG(rating), 0.0) FROM spot_review WHERE spot_id = #{spotId}")
    BigDecimal getAverageRating(Long spotId);
}
