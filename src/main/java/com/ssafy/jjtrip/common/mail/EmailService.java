package com.ssafy.jjtrip.common.mail;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    @Value("${spring.mail.username}")
    private String fromAddress;

    private static final String SUBJECT_NEW_PASSWORD = "[JJTRIP] 임시 비밀번호 안내";
    private static final String TEXT_NEW_PASSWORD = "안녕하세요, JJTRIP입니다.\n\n"
            + "요청하신 임시 비밀번호는 다음과 같습니다:\n\n"
            + "%s\n\n"
            + "로그인 후 반드시 비밀번호를 변경해주세요.\n\n"
            + "감사합니다.";

    private final JavaMailSender mailSender;

    @Async
    public void sendNewPasswordEmail(String to, String newPassword) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(to);
        message.setSubject(SUBJECT_NEW_PASSWORD);
        message.setText(String.format(TEXT_NEW_PASSWORD, newPassword));
        mailSender.send(message);
    }
}