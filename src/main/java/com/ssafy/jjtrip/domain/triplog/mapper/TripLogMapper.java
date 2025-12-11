package com.ssafy.jjtrip.domain.triplog.mapper;

import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogImageResponseDto;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogComment;
import org.apache.ibatis.annotations.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Mapper
public interface TripLogMapper {

    @Select("SELECT " +
            "tl.id as logId, " +
            "tl.title, " +
            "tl.content, " +
            "tl.location_summary as locationSummary, " +
            "tl.like_count as likeCount, " +
            "tl.comment_count as commentCount, " +
            "tl.created_at as createdAt, " +
            "u.nickname as authorNickname, " +
            "u.profile_image_url as authorImageUrl, " +
            "t.id as tripId, " +
            "t.title as tripTitle " +
            "FROM trip_log tl " +
            "JOIN trip t ON tl.trip_id = t.id " +
            "JOIN user u ON t.user_id = u.id " +
            "WHERE tl.id = #{logId}")
    @ConstructorArgs({
            @Arg(column = "logId", javaType = Long.class),
            @Arg(column = "title", javaType = String.class),
            @Arg(column = "content", javaType = String.class),
            @Arg(column = "locationSummary", javaType = String.class),
            @Arg(column = "likeCount", javaType = int.class),
            @Arg(column = "commentCount", javaType = int.class),
            @Arg(column = "createdAt", javaType = LocalDateTime.class),
            @Arg(column = "authorNickname", javaType = String.class),
            @Arg(column = "authorImageUrl", javaType = String.class),
            @Arg(column = "tripId", javaType = Long.class),
            @Arg(column = "tripTitle", javaType = String.class)
    })
    Optional<TripLogDetailResponseDto.BaseInfo> findDetailById(Long logId);

    @Select("SELECT " +
            "image_ref_key, " +
            "image_url, " +
            "order_index " +
            "FROM log_image " +
            "WHERE log_id = #{logId} " +
            "ORDER BY order_index ASC")
    @ConstructorArgs({
            @Arg(column = "image_ref_key", javaType = String.class),
            @Arg(column = "image_url", javaType = String.class),
            @Arg(column = "order_index", javaType = int.class)
    })
    List<TripLogImageResponseDto> findImagesByLogId(Long logId);

    @Select("SELECT " +
            "c.id as commentId, " +
            "u.nickname as authorNickname, " +
            "u.profile_image_url as authorImageUrl, " +
            "c.content, " +
            "c.created_at as createdAt " +
            "FROM log_comment c " +
            "JOIN user u ON c.user_id = u.id " +
            "WHERE c.log_id = #{logId} " +
            "ORDER BY c.created_at ASC")
    @ConstructorArgs({
            @Arg(column = "commentId", javaType = Long.class),
            @Arg(column = "authorNickname", javaType = String.class),
            @Arg(column = "authorImageUrl", javaType = String.class),
            @Arg(column = "content", javaType = String.class),
            @Arg(column = "createdAt", javaType = LocalDateTime.class)
    })
    List<TripLogCommentResponseDto> findCommentsByLogId(Long logId);

    @Select("SELECT EXISTS(SELECT 1 FROM trip_log WHERE id = #{logId})")
    boolean existsById(Long logId);

    @Insert("INSERT INTO log_comment (log_id, user_id, content) " +
            "VALUES (#{comment.logId}, #{comment.userId}, #{comment.content})")
    @Options(useGeneratedKeys = true, keyProperty = "comment.id")
    void insertComment(@Param("comment") TripLogComment comment);

    @Update("UPDATE trip_log SET comment_count = comment_count + 1 WHERE id = #{logId}")
    void incrementCommentCount(Long logId);

    // Like/Unlike methods
    @Insert("INSERT IGNORE INTO log_like (log_id, user_id) VALUES (#{logId}, #{userId})")
    void insertLike(@Param("logId") Long logId, @Param("userId") Long userId);

    @Delete("DELETE FROM log_like WHERE log_id = #{logId} AND user_id = #{userId}")
    void deleteLike(@Param("logId") Long logId, @Param("userId") Long userId);

    @Update("UPDATE trip_log SET like_count = like_count + 1 WHERE id = #{logId}")
    void incrementLikeCount(Long logId);

    @Update("UPDATE trip_log SET like_count = like_count - 1 WHERE id = #{logId}")
    void decrementLikeCount(Long logId);

    @Select("SELECT EXISTS(SELECT 1 FROM log_like WHERE log_id = #{logId} AND user_id = #{userId})")
    boolean hasUserLiked(@Param("logId") Long logId, @Param("userId") Long userId);

    @Select("SELECT like_count FROM trip_log WHERE id = #{logId}")
    int getLikeCount(Long logId);
}

