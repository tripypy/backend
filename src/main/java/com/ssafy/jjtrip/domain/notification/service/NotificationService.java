package com.ssafy.jjtrip.domain.notification.service;

import com.ssafy.jjtrip.domain.notification.dto.NotificationResponseDto;
import com.ssafy.jjtrip.domain.notification.entity.Notification;
import com.ssafy.jjtrip.domain.notification.entity.NotificationType;
import com.ssafy.jjtrip.domain.notification.exception.NotificationErrorCode;
import com.ssafy.jjtrip.domain.notification.exception.NotificationException;
import com.ssafy.jjtrip.domain.notification.mapper.NotificationMapper;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final NotificationMapper notificationMapper;
    private final UserMapper userMapper;
    private final Map<Long, SseEmitter> emitters = new ConcurrentHashMap<>();
    private static final Long DEFAULT_TIMEOUT = 60L * 1000 * 60;

    public SseEmitter subscribe(Long userId) {
        SseEmitter emitter = new SseEmitter(DEFAULT_TIMEOUT);
        emitters.put(userId, emitter);

        emitter.onCompletion(() -> emitters.remove(userId));
        emitter.onTimeout(() -> emitters.remove(userId));
        emitter.onError((e) -> emitters.remove(userId));

        try {
            emitter.send(SseEmitter.event()
                    .name("connect")
                    .data("연결되었습니다!"));
        } catch (IOException e) {
            emitters.remove(userId);
            log.error("사용자 {}의 SSE 연결 이벤트 전송 중 오류 발생", userId, e);
        }

        return emitter;
    }

    @Transactional
    public void send(Long senderId, Long receiverId, NotificationType type, String parameter, Long targetId, String targetUrl) {
        if (senderId.equals(receiverId)) {
            return;
        }

        User sender = userMapper.findById(senderId)
                .orElseThrow(() -> new NotificationException(NotificationErrorCode.SENDER_NOT_FOUND));

        String message;
        if (type == NotificationType.COMMENT) {
            String content = parameter != null ? parameter : "";
            if (content.length() > 20) {
                content = content.substring(0, 20) + "...";
            }
            message = String.format(type.getMessageTemplate(), sender.getNickname(), content);
        } else {
            message = String.format(type.getMessageTemplate(), sender.getNickname());
        }

        Notification notification = Notification.builder()
                .receiverId(receiverId)
                .senderId(senderId)
                .type(type)
                .message(message)
                .targetId(targetId)
                .targetUrl(targetUrl)
                .isRead(false)
                .createdAt(java.time.LocalDateTime.now())
                .build();
        
        notificationMapper.save(notification);

        if (emitters.containsKey(receiverId)) {
            SseEmitter emitter = emitters.get(receiverId);
            try {
                NotificationResponseDto responseDto = NotificationResponseDto.from(notification, sender.getNickname(), sender.getProfileImageUrl());
                emitter.send(SseEmitter.event()
                        .name("notification")
                        .data(responseDto));
            } catch (IOException e) {
                emitters.remove(receiverId);
                log.error("사용자 {}에게 알림 전송 실패", receiverId, e);
            }
        }
    }

    @Transactional(readOnly = true)
    public List<NotificationResponseDto> findAll(Long userId) {
        List<Notification> notifications = notificationMapper.findAllByUserId(userId);
        
        return notifications.stream()
                .map(n -> {
                    User sender = userMapper.findById(n.getSenderId()).orElse(null);
                    String nickname = (sender != null) ? sender.getNickname() : "알 수 없는 사용자";
                    String profileImage = (sender != null) ? sender.getProfileImageUrl() : null;
                    
                    return NotificationResponseDto.from(n, nickname, profileImage);
                })
                .collect(Collectors.toList());
    }

    @Transactional
    public void markAsRead(Long notificationId) {
        notificationMapper.markAsRead(notificationId);
    }

    @Transactional
    public void markAllAsRead(Long userId) {
        notificationMapper.markAllAsRead(userId);
    }
    
    @Transactional
    public void delete(Long notificationId) {
        notificationMapper.deleteById(notificationId);
    }
}
