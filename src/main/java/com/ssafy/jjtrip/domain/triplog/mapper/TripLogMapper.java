package com.ssafy.jjtrip.domain.triplog.mapper;

import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogCommentFlatDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogDetailResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogFeedResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogImageResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.response.TripLogSummaryDto;
import com.ssafy.jjtrip.domain.triplog.entity.TripLog;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogComment;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogVisibility;
import com.ssafy.jjtrip.domain.user.dto.AiAnalysisRequestDto;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.apache.ibatis.annotations.Arg;
import org.apache.ibatis.annotations.ConstructorArgs;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

@Mapper
public interface TripLogMapper {

    record ImageInfo(Long logId, String imageRefKey, String imageUrl, int orderIndex) {}
    record LogImageInsertInfo(Long logId, Long userId, String imageUrl, int orderIndex, String imageRefKey) {}

    @Insert("INSERT INTO trip_log (trip_id, title, content, visibility) VALUES (#{tripId}, #{title}, #{content}, #{visibility})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insertTripLog(TripLog tripLog);

    @Insert("INSERT INTO log_image (log_id, user_id, image_url, order_index, image_ref_key) " +
            "VALUES (#{logId}, #{userId}, #{imageUrl}, #{orderIndex}, #{imageRefKey})")
    void insertTripLogImage(LogImageInsertInfo imageInfo);

    @Delete("DELETE FROM log_image WHERE log_id = #{logId}")
    void deleteLogImages(Long logId);

    @Select("SELECT EXISTS(SELECT 1 FROM trip_log WHERE trip_id = #{tripId})")
    boolean existsByTripId(Long tripId);

    @Select("""
            <script>
            SELECT
                tl.id as logId,
                u.id as authorId,
                u.nickname as authorNickname,
                u.profile_image_url as authorImageUrl,
                tl.title,
                tl.content,
                t.location_summary as locationSummary,
                (SELECT COUNT(*) FROM log_like ll WHERE ll.log_id = tl.id) as likeCount,
                (SELECT COUNT(*) FROM log_comment lc WHERE lc.log_id = tl.id) as commentCount,
                <if test="memberId != null">
                    EXISTS(SELECT 1 FROM log_like ll WHERE ll.log_id = tl.id AND ll.user_id = #{memberId}) as liked,
                </if>
                <if test="memberId == null">
                    0 as liked,
                </if>
                tl.created_at as createdAt
            FROM
                trip_log tl
            JOIN
                trip t ON tl.trip_id = t.id
            JOIN
                user u ON t.user_id = u.id
            <where>
                <if test="cursor != null">
                    tl.id &lt; #{cursor}
                </if>
                AND tl.visibility = 'PUBLIC'
                AND t.visibility = 'PUBLIC'
            </where>
            ORDER BY
                tl.id DESC
            LIMIT #{limit}
            </script>
            """)
    List<TripLogFeedResponseDto.FeedData> findTripLogFeed(@Param("cursor") Long cursor, @Param("limit") int limit, @Param("memberId") Long memberId);

    @Select("""
            <script>
            SELECT
                tl.id as logId,
                u.id as authorId,
                u.nickname as authorNickname,
                u.profile_image_url as authorImageUrl,
                tl.title,
                tl.content,
                t.location_summary as locationSummary,
                (SELECT COUNT(*) FROM log_like ll WHERE ll.log_id = tl.id) as likeCount,
                (SELECT COUNT(*) FROM log_comment lc WHERE lc.log_id = tl.id) as commentCount,
                <if test="memberId != null">
                    EXISTS(SELECT 1 FROM log_like ll WHERE ll.log_id = tl.id AND ll.user_id = #{memberId}) as liked,
                </if>
                <if test="memberId == null">
                    0 as liked,
                </if>
                tl.created_at as createdAt
            FROM
                trip_log tl
            JOIN
                trip t ON tl.trip_id = t.id
            JOIN
                user u ON t.user_id = u.id
            <where>
                AND u.id = #{authorId}
                <choose>
                    <when test="memberId != null and memberId == authorId">
                    </when>
                    <otherwise>
                        AND tl.visibility = 'PUBLIC' AND t.visibility = 'PUBLIC'
                    </otherwise>
                </choose>
            </where>
            ORDER BY
                tl.id DESC
            LIMIT #{limit} OFFSET #{offset}
            </script>
            """)
    List<TripLogFeedResponseDto.FeedData> findTripLogsByUserId(@Param("offset") int offset, @Param("limit") int limit, @Param("memberId") Long memberId, @Param("authorId") Long authorId);

    @Select("""
            <script>
            SELECT
                tl.id as logId,
                u.id as authorId,
                u.nickname as authorNickname,
                u.profile_image_url as authorImageUrl,
                tl.title,
                tl.content,
                t.location_summary as locationSummary,
                (SELECT COUNT(*) FROM log_like ll WHERE ll.log_id = tl.id) as likeCount,
                (SELECT COUNT(*) FROM log_comment lc WHERE lc.log_id = tl.id) as commentCount,
                <if test="memberId != null">
                    EXISTS(SELECT 1 FROM log_like ll WHERE ll.log_id = tl.id AND ll.user_id = #{memberId}) as liked,
                </if>
                <if test="memberId == null">
                    0 as liked,
                </if>
                tl.created_at as createdAt
            FROM
                trip_log tl
            JOIN
                trip t ON tl.trip_id = t.id
            JOIN
                user u ON t.user_id = u.id
            WHERE
                tl.visibility = 'PUBLIC'
                AND t.visibility = 'PUBLIC'
                AND EXISTS (
                    SELECT 1 FROM trip_item ti 
                    WHERE ti.trip_id = t.id 
                    AND ti.spot_id = #{spotId}
                )
                <if test="cursor != null">
                    AND tl.id &lt; #{cursor}
                </if>
            ORDER BY
                tl.id DESC
            LIMIT #{limit}
            </script>
            """)
    List<TripLogFeedResponseDto.FeedData> findTripLogsBySpotId(@Param("spotId") Long spotId, @Param("cursor") Long cursor, @Param("limit") int limit, @Param("memberId") Long memberId);

    @Select("""
            <script>
            SELECT COUNT(*)
            FROM trip_log tl
            JOIN trip t ON tl.trip_id = t.id
            JOIN user u ON t.user_id = u.id
            <where>
                AND u.id = #{authorId}
                <choose>
                    <when test="memberId != null and memberId == authorId">
                    </when>
                    <otherwise>
                        AND tl.visibility = 'PUBLIC' AND t.visibility = 'PUBLIC'
                    </otherwise>
                </choose>
            </where>
            </script>
            """)
    long countTripLogsByUserId(@Param("memberId") Long memberId, @Param("authorId") Long authorId);

    @Select("""
            <script>
            SELECT
                log_id,
                image_ref_key,
                image_url,
                order_index
            FROM
                log_image
            WHERE
                log_id IN
                <foreach item='item' collection='logIds' open='(' separator=',' close=')'>
                    #{item}
                </foreach>
            ORDER BY
                log_id, order_index ASC
            </script>
            """)
    List<ImageInfo> findImagesByLogIds(@Param("logIds") List<Long> logIds);

    @Select("SELECT " +
            "tl.id as logId, " +
            "tl.title, " +
            "tl.content, " +
            "t.location_summary as locationSummary, " +
            "tl.created_at as createdAt, " +
            "u.id as authorId, " +
            "u.nickname as authorNickname, " +
            "u.profile_image_url as authorImageUrl, " +
            "tl.visibility as visibility, " +
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
            @Arg(column = "createdAt", javaType = LocalDateTime.class),
            @Arg(column = "authorId", javaType = Long.class),
            @Arg(column = "authorNickname", javaType = String.class),
            @Arg(column = "authorImageUrl", javaType = String.class),
            @Arg(column = "visibility", javaType = TripLogVisibility.class),
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
            "u.id as authorId, " +
            "u.nickname as authorNickname, " +
            "u.profile_image_url as authorImageUrl, " +
            "c.content, " +
            "c.parent_id as parentId, " +
            "c.is_deleted as isDeleted, " +
            "c.created_at as createdAt " +
            "FROM log_comment c " +
            "JOIN user u ON c.user_id = u.id " +
            "WHERE c.log_id = #{logId} " +
            "ORDER BY c.created_at ASC")

    @ConstructorArgs({
            @Arg(column = "commentId", javaType = Long.class),
            @Arg(column = "authorId", javaType = Long.class),
            @Arg(column = "authorNickname", javaType = String.class),
            @Arg(column = "authorImageUrl", javaType = String.class),
            @Arg(column = "content", javaType = String.class),
            @Arg(column = "parentId", javaType = Long.class),
            @Arg(column = "isDeleted", javaType = boolean.class),
            @Arg(column = "createdAt", javaType = LocalDateTime.class)
    })
    List<TripLogCommentFlatDto> findCommentsByLogId(Long logId);

    @Select("SELECT EXISTS(SELECT 1 FROM trip_log WHERE id = #{logId})")
    boolean existsById(Long logId);

    @Insert("INSERT INTO log_comment (log_id, user_id, parent_id, content) " +
            "VALUES (#{comment.logId}, #{comment.userId}, #{comment.parentId}, #{comment.content})")
    @Options(useGeneratedKeys = true, keyProperty = "comment.id")
    void insertComment(@Param("comment") TripLogComment comment);

    @Select("SELECT COUNT(*) FROM log_comment WHERE log_id = #{logId}")
    int getCommentCount(Long logId);

    @Insert("INSERT IGNORE INTO log_like (log_id, user_id) VALUES (#{logId}, #{userId})")
    void insertLike(@Param("logId") Long logId, @Param("userId") Long userId);

    @Delete("DELETE FROM log_like WHERE log_id = #{logId} AND user_id = #{userId}")
    void deleteLike(@Param("logId") Long logId, @Param("userId") Long userId);

    @Select("SELECT EXISTS(SELECT 1 FROM log_like WHERE log_id = #{logId} AND user_id = #{userId})")
    boolean hasUserLiked(@Param("logId") Long logId, @Param("userId") Long userId);

    @Select("SELECT COUNT(*) FROM log_like WHERE log_id = #{logId}")
    int getLikeCount(Long logId);

    @Update("""
            <script>
            UPDATE trip_log
            <set>
                <if test="title != null">title = #{title},</if>
                <if test="content != null">content = #{content},</if>
                <if test="visibility != null">visibility = #{visibility},</if>
                updated_at = NOW()
            </set>
            WHERE id = #{id}
            </script>
            """)
    void updateTripLog(TripLog tripLog);

    @Select("""
            SELECT t.user_id
            FROM trip_log tl
            JOIN trip t ON tl.trip_id = t.id
            WHERE tl.id = #{logId}
            """)
    Optional<Long> findAuthorIdByLogId(Long logId);

    @Select("SELECT id, trip_id, title, content, visibility, created_at, updated_at FROM trip_log WHERE id = #{id}")
    Optional<TripLog> findById(Long id);

    @Select("SELECT id, trip_id, title, content, visibility, created_at, updated_at FROM trip_log WHERE trip_id = #{tripId}")
    List<TripLog> findByTripId(Long tripId);

    @Delete("DELETE FROM trip_log WHERE id = #{logId}")
    void deleteTripLog(Long logId);

    @Select("SELECT log_id FROM log_comment WHERE id = #{commentId}")
    Optional<Long> findLogIdByCommentId(Long commentId);

    @Select("""
            <script>
            SELECT
                tl.id AS logId,
                u.id AS authorId,
                u.nickname AS authorNickname,
                u.profile_image_url AS authorImageUrl,
                tl.title,
                tl.content,
                t.location_summary AS locationSummary,
                (SELECT COUNT(*) FROM log_like ll WHERE ll.log_id = tl.id) AS likeCount,
                (SELECT COUNT(*) FROM log_comment lc WHERE lc.log_id = tl.id) AS commentCount,
                <if test="memberId != null">
                    EXISTS(SELECT 1 FROM log_like ll WHERE ll.log_id = tl.id AND ll.user_id = #{memberId}) AS liked,
                </if>
                <if test="memberId == null">
                    0 AS liked,
                </if>
                tl.created_at AS createdAt
            FROM trip_log tl
            JOIN trip t ON tl.trip_id = t.id
            JOIN user u ON t.user_id = u.id
            WHERE tl.visibility = 'PUBLIC'
            AND t.visibility = 'PUBLIC'
            AND tl.id IN
            <foreach item='item' collection='logIds' open='(' separator=',' close=')'>
                #{item}
            </foreach>
            ORDER BY FIELD(tl.id,
            <foreach item='item' collection='logIds' separator=','>
                #{item}
            </foreach>
            )
            </script>
            """)
    List<TripLogFeedResponseDto.FeedData> findLogsByIds(@Param("logIds") List<Long> logIds, @Param("memberId") Long memberId);

    @Select("""
            SELECT tl.id AS logId, tl.trip_id AS tripId, tl.title,
            (SELECT tli.image_url FROM log_image tli WHERE tli.log_id = tl.id ORDER BY tli.order_index ASC LIMIT 1) AS thumbnailUrl
            FROM trip_log tl
            JOIN trip t ON tl.trip_id = t.id
            WHERE t.user_id = #{userId}
            """)
    List<TripLogSummaryDto> findSummariesByUserId(@Param("userId") Long userId);

    @Select("""
            SELECT 
                tl.title,
                tl.content,
                (
                    SELECT GROUP_CONCAT(DISTINCT s.category SEPARATOR ', ')
                    FROM trip_item ti
                    JOIN spot s ON ti.spot_id = s.id
                    WHERE ti.trip_id = t.id
                ) as spotCategories
            FROM trip_log tl
            JOIN trip t ON tl.trip_id = t.id
            WHERE t.user_id = #{userId}
            """)
    @ConstructorArgs({
            @Arg(column = "title", javaType = String.class),
            @Arg(column = "content", javaType = String.class),
            @Arg(column = "spotCategories", javaType = String.class)
    })
    List<AiAnalysisRequestDto.LogItem> findLogsForAnalysis(Long userId);

    @Update("UPDATE log_comment SET content = #{content}, updated_at = NOW() WHERE id = #{commentId}")
    void updateComment(@Param("commentId") Long commentId, @Param("content") String content);

    @Delete("DELETE FROM log_comment WHERE id = #{commentId}")
    void deleteComment(Long commentId);

    @Update("UPDATE log_comment SET is_deleted = TRUE WHERE id = #{commentId}")
    void softDeleteComment(Long commentId);

    @Select("SELECT is_deleted FROM log_comment WHERE id = #{commentId}")
    Optional<Boolean> isCommentDeleted(Long commentId);

    @Select("SELECT EXISTS(SELECT 1 FROM log_comment WHERE parent_id = #{commentId} AND is_deleted = FALSE)")
    boolean hasReplies(Long commentId);

    @Select("SELECT user_id FROM log_comment WHERE id = #{commentId}")
    Optional<Long> findCommentAuthorId(Long commentId);
}