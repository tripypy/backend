package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentFlatDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentResponseDto;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogComment;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogErrorCode;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogException;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripLogCommentService {

    private final TripLogMapper tripLogMapper;

    @Transactional
    public void addComment(Long logId, Long userId, TripLogCommentRequestDto commentRequestDto) {
        validateCommentRequest(logId, commentRequestDto.parentId());

        TripLogComment comment = TripLogComment.builder()
                .logId(logId)
                .userId(userId)
                .parentId(commentRequestDto.parentId())
                .content(commentRequestDto.content())
                .build();
        tripLogMapper.insertComment(comment);
    }

    @Transactional
    public void updateComment(Long userId, Long commentId, String content) {
        validateCommentAuthor(userId, commentId);

        if (tripLogMapper.isCommentDeleted(commentId).orElse(false)) {
            throw new TripLogException(TripLogErrorCode.COMMENT_NOT_FOUND);
        }

        tripLogMapper.updateComment(commentId, content);
    }

    @Transactional
    public void deleteComment(Long userId, Long commentId) {
        validateCommentAuthor(userId, commentId);

        if (tripLogMapper.hasReplies(commentId)) {
            tripLogMapper.softDeleteComment(commentId);
        } else {
            tripLogMapper.deleteComment(commentId);
        }
    }

    public List<TripLogCommentResponseDto> getCommentsByLogId(Long logId) {
        List<TripLogCommentFlatDto> flatComments = tripLogMapper.findCommentsByLogId(logId);
        return organizeComments(flatComments);
    }

    public int getCommentCount(Long logId) {
        return tripLogMapper.getCommentCount(logId);
    }

    private void validateCommentRequest(Long logId, Long parentId) {
        if (!tripLogMapper.existsById(logId)) {
            throw new TripLogException(TripLogErrorCode.LOG_NOT_FOUND);
        }

        if (parentId != null) {
            Long parentLogId = tripLogMapper.findLogIdByCommentId(parentId)
                    .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

            if (!parentLogId.equals(logId)) {
                throw new TripLogException(TripLogErrorCode.FORBIDDEN_ACCESS);
            }

            if (tripLogMapper.isCommentDeleted(parentId).orElse(false)) {
                throw new TripLogException(TripLogErrorCode.COMMENT_NOT_FOUND);
            }
        }
    }

    private void validateCommentAuthor(Long userId, Long commentId) {
        Long authorId = tripLogMapper.findCommentAuthorId(commentId)
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        if (!authorId.equals(userId)) {
            throw new TripLogException(TripLogErrorCode.FORBIDDEN_ACCESS);
        }
    }

    private List<TripLogCommentResponseDto> organizeComments(List<TripLogCommentFlatDto> flatComments) {
        Map<Long, TripLogCommentResponseDto> dtoMap = convertToDtoMap(flatComments);
        return buildHierarchy(flatComments, dtoMap);
    }

    private Map<Long, TripLogCommentResponseDto> convertToDtoMap(List<TripLogCommentFlatDto> flatComments) {
        Map<Long, TripLogCommentResponseDto> dtoMap = new java.util.HashMap<>();
        for (TripLogCommentFlatDto flat : flatComments) {
            String content = flat.isDeleted() ? "삭제된 댓글입니다." : flat.content();
            String authorNickname = flat.isDeleted() ? "(삭제)" : flat.authorNickname();
            String authorImageUrl = flat.isDeleted() ? null : flat.authorImageUrl();

            TripLogCommentResponseDto dto = new TripLogCommentResponseDto(
                    flat.commentId(),
                    authorNickname,
                    authorImageUrl,
                    content,
                    flat.parentId(),
                    flat.createdAt(),
                    new java.util.ArrayList<>()
            );
            dtoMap.put(flat.commentId(), dto);
        }
        return dtoMap;
    }

    private List<TripLogCommentResponseDto> buildHierarchy(List<TripLogCommentFlatDto> flatComments, Map<Long, TripLogCommentResponseDto> dtoMap) {
        List<TripLogCommentResponseDto> roots = new java.util.ArrayList<>();
        for (TripLogCommentFlatDto flat : flatComments) {
            TripLogCommentResponseDto currentDto = dtoMap.get(flat.commentId());
            if (flat.parentId() == null) {
                roots.add(currentDto);
            } else {
                TripLogCommentResponseDto parentDto = dtoMap.get(flat.parentId());
                if (parentDto != null) {
                    parentDto.replies().add(currentDto);
                } else {
                    throw new TripLogException(TripLogErrorCode.DATA_INTEGRITY_ERROR);
                }
            }
        }
        return roots;
    }
}
