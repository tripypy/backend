package com.ssafy.jjtrip.domain.trip.mapper;

import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.entity.TripVisibility;
import java.util.List;
import java.util.Optional;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.apache.ibatis.type.EnumTypeHandler;

@Mapper
public interface TripMapper {

    @Insert("INSERT INTO trip (user_id, trip_status_id, visibility, title, start_date, end_date) " +
            "VALUES (#{userId}, #{status, typeHandler=com.ssafy.jjtrip.domain.trip.mapper.TripStatusIdTypeHandler}, #{visibility, typeHandler=org.apache.ibatis.type.EnumTypeHandler}, #{title}, #{startDate}, #{endDate})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insert(Trip trip);

    @Select("SELECT id, user_id, trip_status_id, visibility, title, start_date, end_date, location_summary, created_at, updated_at " +
            "FROM trip WHERE user_id = #{userId} ORDER BY created_at DESC")
    @Results({
            @Result(property = "userId", column = "user_id"),
            @Result(property = "status", column = "trip_status_id", javaType = TripStatus.class, typeHandler = TripStatusIdTypeHandler.class),
            @Result(property = "visibility", column = "visibility", javaType = TripVisibility.class, typeHandler = EnumTypeHandler.class),
            @Result(property = "startDate", column = "start_date"),
            @Result(property = "endDate", column = "end_date"),
            @Result(property = "locationSummary", column = "location_summary"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    List<Trip> selectByUserId(Long userId);

    @Select("SELECT id, user_id, trip_status_id, visibility, title, start_date, end_date, location_summary, created_at, updated_at " +
            "FROM trip WHERE user_id = #{userId} AND trip_status_id = #{status, typeHandler=com.ssafy.jjtrip.domain.trip.mapper.TripStatusIdTypeHandler} ORDER BY created_at DESC")
    @Results({
            @Result(property = "userId", column = "user_id"),
            @Result(property = "status", column = "trip_status_id", javaType = TripStatus.class, typeHandler = TripStatusIdTypeHandler.class),
            @Result(property = "visibility", column = "visibility", javaType = TripVisibility.class, typeHandler = EnumTypeHandler.class),
            @Result(property = "startDate", column = "start_date"),
            @Result(property = "endDate", column = "end_date"),
            @Result(property = "locationSummary", column = "location_summary"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    List<Trip> selectByUserIdAndStatus(@Param("userId") Long userId, @Param("status") TripStatus status);

    @Select("SELECT id, user_id, trip_status_id, visibility, title, start_date, end_date, location_summary, created_at, updated_at " +
            "FROM trip WHERE id = #{tripId}")
    @Results({
            @Result(property = "userId", column = "user_id"),
            @Result(property = "status", column = "trip_status_id", javaType = TripStatus.class, typeHandler = TripStatusIdTypeHandler.class),
            @Result(property = "visibility", column = "visibility", javaType = TripVisibility.class, typeHandler = EnumTypeHandler.class),
            @Result(property = "startDate", column = "start_date"),
            @Result(property = "endDate", column = "end_date"),
            @Result(property = "locationSummary", column = "location_summary"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    Optional<Trip> selectById(Long tripId);

    @Select("SELECT " +
            "ti.id, ti.trip_id, ti.spot_id, ti.day_number, ti.order_index,  " +
            "s.id as s_id, s.kakao_place_id as s_kakao_place_id, s.name as s_name, s.address as s_address, s.category as s_category, " +
            "s.lat as s_lat, s.lng as s_lng, s.place_url as s_place_url, s.thumbnail_url as s_thumbnail_url " +
            "FROM trip_item ti " +
            "JOIN spot s ON ti.spot_id = s.id " +
            "WHERE ti.trip_id = #{tripId} " +
            "ORDER BY ti.day_number, ti.order_index")
    @Results({
            @Result(property = "id", column = "id"),
            @Result(property = "tripId", column = "trip_id"),
            @Result(property = "spotId", column = "spot_id"),
            @Result(property = "dayNumber", column = "day_number"),
            @Result(property = "orderIndex", column = "order_index"),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "spot.id", column = "s_id"),
            @Result(property = "spot.kakaoPlaceId", column = "s_kakao_place_id"),
            @Result(property = "spot.name", column = "s_name"),
            @Result(property = "spot.address", column = "s_address"),
            @Result(property = "spot.category", column = "s_category"),
            @Result(property = "spot.lat", column = "s_lat"),
            @Result(property = "spot.lng", column = "s_lng"),
            @Result(property = "spot.placeUrl", column = "s_place_url"),
            @Result(property = "spot.thumbnailUrl", column = "s_thumbnail_url")
    })
    List<TripItem> selectItemsWithSpotsByTripId(Long tripId);

    @Update("UPDATE trip SET " +
            "title = #{title}, " +
            "start_date = #{startDate}, " +
            "end_date = #{endDate}, " +
            "trip_status_id = #{status, typeHandler=com.ssafy.jjtrip.domain.trip.mapper.TripStatusIdTypeHandler}, " +
            "visibility = #{visibility, typeHandler=org.apache.ibatis.type.EnumTypeHandler}, " +
            "WHERE id = #{id}")
    void update(Trip trip);

    @Delete("DELETE FROM trip WHERE id = #{tripId}")
    void delete(Long tripId);

    @Select("SELECT COUNT(id) FROM trip_item WHERE trip_id = #{tripId}")
    int countTripItemsByTripId(Long tripId);

    @Select("SELECT s.name FROM trip_item ti JOIN spot s ON ti.spot_id = s.id WHERE ti.trip_id = #{tripId} ORDER BY ti.day_number, ti.order_index LIMIT 3")
    List<String> selectSpotPreviewNamesByTripId(Long tripId);

    @Select("""
        SELECT EXISTS (
            SELECT 1
            FROM trip
            WHERE id = #{tripId} AND user_id = #{userId}
        )
    """)
    boolean existsByIdAndUserId(@Param("tripId") Long tripId, @Param("userId") Long userId);

    @Delete("""
        DELETE FROM trip_item
        WHERE trip_id = #{tripId}
    """)
    int deleteTripItemsByTripId(@Param("tripId") Long tripId);

    @Insert("""
        INSERT INTO trip_item (trip_id, spot_id, day_number, order_index)
        VALUES (#{tripId}, #{spotId}, #{dayNumber}, #{orderIndex})
    """)
    int insertTripItem(
            @Param("tripId") Long tripId,
            @Param("spotId") Long spotId,
            @Param("dayNumber") int dayNumber,
            @Param("orderIndex") int orderIndex
    );

    @Update("""
        UPDATE trip
        SET location_summary = #{locationSummary}, updated_at = NOW()
        WHERE id = #{tripId}
    """)
    int updateLocationSummary(@Param("tripId") Long tripId, @Param("locationSummary") String locationSummary);
}
