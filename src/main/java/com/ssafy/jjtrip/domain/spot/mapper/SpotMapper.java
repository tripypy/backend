package com.ssafy.jjtrip.domain.spot.mapper;

import com.ssafy.jjtrip.domain.spot.entity.Spot;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;

import java.util.Optional;

@Mapper
public interface SpotMapper {

    @Select("SELECT id, kakao_place_id, name, address, category, lat, lng, place_url, thumbnail_url, review_count, average_rating, created_at " +
            "FROM spot WHERE kakao_place_id = #{kakaoPlaceId}")
    Optional<Spot> findByKakaoPlaceId(String kakaoPlaceId);

    @Insert("INSERT INTO spot (kakao_place_id, name, address, category, lat, lng, place_url, thumbnail_url) " +
            "VALUES (#{kakaoPlaceId}, #{name}, #{address}, #{category}, #{lat}, #{lng}, #{placeUrl}, #{thumbnailUrl})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insert(Spot spot);
}
