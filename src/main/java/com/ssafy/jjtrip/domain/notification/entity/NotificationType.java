package com.ssafy.jjtrip.domain.notification.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum NotificationType {
    LIKE("LIKE", "%s님이 회원님의 게시물에 좋아요를 눌렀습니다."), // 핑크색
    COMMENT("COMMENT", "%s님이 댓글을 남겼습니다: \"%s\""), // 파란색
    FRIEND_REQUEST("FRIEND_REQUEST", "%s님이 회원님에게 친구 요청을 보냈습니다."), // 청록색
    FRIEND_ACCEPT("FRIEND_ACCEPT", "%s님에게 보낸 친구 신청이 수락되었습니다."), // 청록색
    SCRAP("SCRAP", "%s님이 회원님의 여행 계획을 스크랩했습니다."); // 노란색

    private final String code;
    private final String messageTemplate;
}
