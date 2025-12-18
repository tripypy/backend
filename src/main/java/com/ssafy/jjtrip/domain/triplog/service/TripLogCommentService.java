package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentFlatDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentRequestDto;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogCommentResponseDto;
import com.ssafy.jjtrip.domain.triplog.entity.TripLogComment;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogErrorCode;
import com.ssafy.jjtrip.domain.triplog.exception.TripLogException;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import java.util.ArrayList;
import java.util.HashMap;
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
        validateAddCommentRequest(logId, commentRequestDto.parentId());

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
        validateCommentOwnership(userId, commentId);
        validateCommentNotDeleted(commentId);

        tripLogMapper.updateComment(commentId, content);
    }

    @Transactional
    public void deleteComment(Long userId, Long commentId) {
        validateCommentOwnership(userId, commentId);

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

    private void validateAddCommentRequest(Long logId, Long parentId) {
        if (!tripLogMapper.existsById(logId)) {
            throw new TripLogException(TripLogErrorCode.LOG_NOT_FOUND);
        }
        if (parentId != null) {
            validateParentComment(logId, parentId);
        }
    }

    private void validateParentComment(Long logId, Long parentId) {
        Long parentLogId = tripLogMapper.findLogIdByCommentId(parentId)
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        if (!parentLogId.equals(logId)) {
            throw new TripLogException(TripLogErrorCode.FORBIDDEN_ACCESS);
        }
        
        validateCommentNotDeleted(parentId);
    }

    private void validateCommentOwnership(Long userId, Long commentId) {
        Long authorId = tripLogMapper.findCommentAuthorId(commentId)
                .orElseThrow(() -> new TripLogException(TripLogErrorCode.LOG_NOT_FOUND));

        if (!authorId.equals(userId)) {
            throw new TripLogException(TripLogErrorCode.FORBIDDEN_ACCESS);
        }
    }

    private void validateCommentNotDeleted(Long commentId) {
        if (tripLogMapper.isCommentDeleted(commentId).orElse(false)) {
            throw new TripLogException(TripLogErrorCode.COMMENT_NOT_FOUND);
        }
    }

    private List<TripLogCommentResponseDto> organizeComments(List<TripLogCommentFlatDto> flatComments) {
        Map<Long, TripLogCommentResponseDto> dtoMap = new HashMap<>();
        List<TripLogCommentResponseDto> roots = new ArrayList<>();

        for (TripLogCommentFlatDto flat : flatComments) {
            TripLogCommentResponseDto dto = convertToResponseDto(flat);
            dtoMap.put(flat.commentId(), dto);
        }

        for (TripLogCommentFlatDto flat : flatComments) {
            TripLogCommentResponseDto currentDto = dtoMap.get(flat.commentId());

            if (flat.parentId() == null) {
                roots.add(currentDto);
            } else {
                linkToParent(flat.parentId(), currentDto, dtoMap);
            }
        }
        return roots;
    }

    private TripLogCommentResponseDto convertToResponseDto(TripLogCommentFlatDto flat) {
        boolean isDeleted = flat.isDeleted();
        String content = isDeleted ? "삭제된 댓글입니다." : flat.content();
        String authorNickname = isDeleted ? "(삭제)" : flat.authorNickname();
        String authorImageUrl = isDeleted ? null : flat.authorImageUrl();

        return new TripLogCommentResponseDto(
                flat.commentId(),
                authorNickname,
                authorImageUrl,
                content,
                flat.parentId(),
                flat.createdAt(),
                new ArrayList<>()
        );
    }

    private void linkToParent(Long parentId, TripLogCommentResponseDto child, Map<Long, TripLogCommentResponseDto> dtoMap) {
        TripLogCommentResponseDto parent = dtoMap.get(parentId);
        if (parent == null) {
            throw new TripLogException(TripLogErrorCode.DATA_INTEGRITY_ERROR);
        }
        parent.replies().add(child);
    }
}
