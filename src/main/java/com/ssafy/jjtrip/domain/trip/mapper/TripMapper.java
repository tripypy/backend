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

    @Update("UPDATE trip SET title = #{title}, start_date = #{startDate}, end_date = #{endDate}, status = #{status} " +
            "WHERE id = #{id}")
    void update(Trip trip);

    @Delete("DELETE FROM trip WHERE id = #{tripId}")
    void delete(Long tripId);

    @Insert({
        "<script>",
        "INSERT INTO trip_item (trip_id, spot_id, day_number, order_index, memo) VALUES ",
        "<foreach item='item' collection='list' separator=','>",
        "(#{item.tripId}, #{item.spotId}, #{item.dayNumber}, #{item.orderIndex}, #{item.memo})",
        "</foreach>",
        "</script>"
    })
    void insertTripItems(@Param("list") List<TripItem> tripItems);
}
