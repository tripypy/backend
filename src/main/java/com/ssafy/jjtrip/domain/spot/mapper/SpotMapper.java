package com.ssafy.jjtrip.domain.spot.mapper;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import java.util.List;
import java.util.Optional;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface SpotMapper {

    @Select("SELECT id, kakao_place_id, name, address, category, lat, lng, place_url, thumbnail_url, review_count, average_rating, created_at " +
            "FROM spot WHERE kakao_place_id = #{kakaoPlaceId}")
    Optional<Spot> findByKakaoPlaceId(String kakaoPlaceId);

    @Insert("INSERT INTO spot (kakao_place_id, name, address, category, lat, lng, place_url, thumbnail_url) " +
            "VALUES (#{kakaoPlaceId}, #{name}, #{address}, #{category}, #{lat}, #{lng}, #{placeUrl}, #{thumbnailUrl})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insert(Spot spot);

    @Select("""
        SELECT EXISTS(
            SELECT 1 FROM spot WHERE id = #{spotId}
        )
    """)
    boolean existsById(@Param("spotId") Long spotId);

    @Select("""
        SELECT s.id, s.kakao_place_id, s.name, s.address, s.category, s.lat, s.lng, 
               s.place_url, s.thumbnail_url, s.review_count, s.average_rating, s.created_at
        FROM spot s
        JOIN trip_item ti ON s.id = ti.spot_id
        GROUP BY s.id
        ORDER BY COUNT(ti.id) DESC
        LIMIT 10
    """)
    List<Spot> findTop10MostAdded();
}
