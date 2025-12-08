package com.ssafy.jjtrip.domain.user.service;

import com.ssafy.jjtrip.common.mail.EmailService;
import com.ssafy.jjtrip.common.s3.S3Service;
import com.ssafy.jjtrip.common.util.EmailMasker;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import com.ssafy.jjtrip.domain.user.dto.response.UserProfileResponseDto;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.security.SecureRandom;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final S3Service s3Service;

    public User findUserById(Long userId) {
        return userMapper.findById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));
    }

    public UserProfileResponseDto getUserProfile(Long userId) {
        User user = findUserById(userId);
        return UserProfileResponseDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .profileImageUrl(user.getProfileImageUrl())
                .build();
    }

    @Transactional
    public void resetPassword(String email) {
        userMapper.findByEmail(email).ifPresent(user -> {
            String temporaryPassword = generateTemporaryPassword();
            String encodedPassword = passwordEncoder.encode(temporaryPassword);
            userMapper.updatePasswordHash(user.getId(), encodedPassword);
            emailService.sendNewPasswordEmail(user.getEmail(), temporaryPassword);
        });
    }

    public String findEmailByNickname(String nickname) {
        User user = userMapper.findByNickname(nickname)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));

        return EmailMasker.maskEmail(user.getEmail());
    }

    @Transactional
    public String updateUserProfileImage(Long userId, MultipartFile profileImage) {

        User user = findUserById(userId);
        String oldImageUrl = user.getProfileImageUrl();
        String newImageUrl = s3Service.uploadProfileImage(profileImage);

        userMapper.updateProfileImageUrl(userId, newImageUrl);

        if (oldImageUrl != null && !oldImageUrl.isEmpty()) {
            s3Service.deleteImage(oldImageUrl);
        }

        return newImageUrl;
    }
    
    private String generateTemporaryPassword() {

        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(10);
        for (int i = 0; i < 10; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        return sb.toString();
    }
}
