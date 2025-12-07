package com.ssafy.jjtrip.domain.trip.mapper;

import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripItem;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
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

@Mapper
public interface TripMapper {

    @Insert("INSERT INTO trip (user_id, title, start_date, end_date, status) " +
            "VALUES (#{userId}, #{title}, #{startDate}, #{endDate}, #{status})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insert(Trip trip);

    @Select("SELECT id, user_id, title, start_date, end_date, status, created_at, updated_at " +
            "FROM trip WHERE user_id = #{userId} ORDER BY created_at DESC")
    @Results({
            @Result(property = "userId", column = "user_id"),
            @Result(property = "startDate", column = "start_date"),
            @Result(property = "endDate", column = "end_date"),
            @Result(property = "status", column = "status", typeHandler = TripStatusTypeHandler.class),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    List<Trip> selectByUserId(Long userId);

    @Select("SELECT id, user_id, title, start_date, end_date, status, created_at, updated_at " +
            "FROM trip WHERE user_id = #{userId} AND status = #{status} ORDER BY created_at DESC")
    @Results({
            @Result(property = "userId", column = "user_id"),
            @Result(property = "startDate", column = "start_date"),
            @Result(property = "endDate", column = "end_date"),
            @Result(property = "status", column = "status", typeHandler = TripStatusTypeHandler.class),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    List<Trip> selectByUserIdAndStatus(@Param("userId") Long userId, @Param("status") TripStatus status);

    @Select("SELECT id, user_id, title, start_date, end_date, status, created_at, updated_at " +
            "FROM trip WHERE id = #{tripId}")
    @Results({
            @Result(property = "userId", column = "user_id"),
            @Result(property = "startDate", column = "start_date"),
            @Result(property = "endDate", column = "end_date"),
            @Result(property = "status", column = "status", typeHandler = TripStatusTypeHandler.class),
            @Result(property = "createdAt", column = "created_at"),
            @Result(property = "updatedAt", column = "updated_at")
    })
    Optional<Trip> selectById(Long tripId);

    @Select("SELECT id, trip_id, spot_id, day_number, order_index, memo, created_at " +
            "FROM trip_item WHERE trip_id = #{tripId} " +
            "ORDER BY day_number, order_index")
    List<TripItem> selectItemsByTripId(Long tripId);

    @Select("SELECT " +
            "ti.id, ti.trip_id, ti.spot_id, ti.day_number, ti.order_index, ti.memo, ti.created_at, " +
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
            @Result(property = "memo", column = "memo"),
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

    @Update("UPDATE trip SET title = #{title}, start_date = #{startDate}, end_date = #{endDate}, status = #{status} " +
            "WHERE id = #{id}")
    void update(Trip trip);

    @Delete("DELETE FROM trip WHERE id = #{tripId}")
    void delete(Long tripId);

    @Insert("INSERT INTO trip_item (trip_id, spot_id, day_number, order_index, memo) " +
            "VALUES (#{tripId}, #{spotId}, #{dayNumber}, #{orderIndex}, #{memo})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insertTripItem(TripItem tripItem);

    @Select("SELECT COUNT(*) > 0 FROM trip_item WHERE trip_id = #{tripId} AND day_number = #{dayNumber} AND order_index = #{orderIndex}")
    boolean existsByTripIdAndDayNumberAndOrderIndex(@Param("tripId") Long tripId, @Param("dayNumber") Integer dayNumber, @Param("orderIndex") Integer orderIndex);

    @Insert({
        "<script>",
        "INSERT INTO trip_item (trip_id, spot_id, day_number, order_index, memo) VALUES ",
        "<foreach item='item' collection='list' separator=','>",
        "(#{item.tripId}, #{item.spotId}, #{item.dayNumber}, #{item.orderIndex}, #{item.memo})",
        "</foreach>",
        "</script>"
    })
    void insertTripItems(@Param("list") List<TripItem> tripItems);

    @Delete({
        "<script>",
        "DELETE FROM trip_item WHERE id IN ",
        "<foreach item='item' collection='list' open='(' separator=',' close=')'>",
        "#{item}",
        "</foreach>",
        "</script>"
    })
    void deleteTripItemsByIds(@Param("list") List<Long> tripItemIds);

    @Update("UPDATE trip_item SET day_number = #{dayNumber}, order_index = #{orderIndex}, memo = #{memo} WHERE id = #{id}")
    void updateTripItemDetails(@Param("id") Long id, @Param("dayNumber") int dayNumber, @Param("orderIndex") int orderIndex, @Param("memo") String memo);

    @Update({
        "<script>",
        "UPDATE trip_item",
        "SET order_index = -order_index",
        "WHERE id IN",
        "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
        "#{id}",
        "</foreach>",
        "</script>"
    })
    void parkTripItems(@Param("ids") List<Long> ids);
}

