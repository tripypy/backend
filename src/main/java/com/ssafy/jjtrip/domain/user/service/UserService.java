package com.ssafy.jjtrip.domain.user.service;

import com.ssafy.jjtrip.common.mail.EmailService;
import com.ssafy.jjtrip.common.s3.S3Service;
import com.ssafy.jjtrip.common.util.EmailMasker;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import com.ssafy.jjtrip.domain.user.dto.request.UpdateUserRequestDto;
import com.ssafy.jjtrip.domain.user.dto.response.PublicUserProfileResponseDto;
import com.ssafy.jjtrip.domain.user.dto.response.UserAndProfileDto;
import com.ssafy.jjtrip.domain.user.dto.response.UserProfileResponseDto;
import com.ssafy.jjtrip.domain.user.entity.User;
import com.ssafy.jjtrip.domain.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final S3Service s3Service;
    
    public UserProfileResponseDto getUserProfile(Long userId) {
        UserAndProfileDto userAndProfile = userMapper.findUserAndProfileById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));

        return mapToUserProfileResponseDto(userAndProfile);
    }
    
    public PublicUserProfileResponseDto getPublicUserProfile(Long userId) {
        UserAndProfileDto userAndProfile = userMapper.findUserAndProfileById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));

        return PublicUserProfileResponseDto.from(userAndProfile);
    }

    public List<PublicUserProfileResponseDto> getFriendsList(Long userId) {
        List<UserAndProfileDto> friends = userMapper.findFriendsByUserId(userId);
        return friends.stream()
                .map(PublicUserProfileResponseDto::from)
                .collect(Collectors.toList());
    }

    @Transactional
    public void updateUserProfile(Long userId, UpdateUserRequestDto updateUserRequestDto) {
        if (StringUtils.hasText(updateUserRequestDto.getNickname())) {
            userMapper.updateNickname(userId, updateUserRequestDto.getNickname());
        }
        if (StringUtils.hasText(updateUserRequestDto.getBio())) {
            userMapper.upsertBio(userId, updateUserRequestDto.getBio());
        }
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
        User user = userMapper.findById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));
        String oldImageUrl = user.getProfileImageUrl();

        // S3에 새 이미지 업로드
        String newImageUrl = s3Service.uploadProfileImage(profileImage);

        // DB에 새 이미지 URL 업데이트
        userMapper.updateProfileImageUrl(userId, newImageUrl);

        // S3에서 기존 이미지 삭제 (존재하는 경우)
        if (StringUtils.hasText(oldImageUrl)) {
            s3Service.deleteImage(oldImageUrl);
        }

        return newImageUrl;
    }

    @Transactional
    public void deleteUserProfileImage(Long userId) {
        User user = userMapper.findById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));
        String imageUrl = user.getProfileImageUrl();

        if (StringUtils.hasText(imageUrl)) {
            s3Service.deleteImage(imageUrl);
            userMapper.deleteProfileImageUrl(userId);
        }
    }

    private UserProfileResponseDto mapToUserProfileResponseDto(UserAndProfileDto userAndProfile) {
        return UserProfileResponseDto.builder()
                .id(userAndProfile.getId())
                .email(userAndProfile.getEmail())
                .nickname(userAndProfile.getNickname())
                .profileImageUrl(userAndProfile.getProfileImageUrl())
                .bio(userAndProfile.getBio())
                .intro(userAndProfile.getIntro())
                .homeRegionId(userAndProfile.getHomeRegionId())
                .travelStyleSummary(userAndProfile.getTravelStyleSummary())
                .travelStyleId(userAndProfile.getTravelStyleId())
                .profileBannerUrl(userAndProfile.getProfileBannerUrl())
                .isProfilePublic(userAndProfile.getIsProfilePublic())
                .friendsCount(userAndProfile.getFriendsCount()) // Pass friendsCount
                .build();
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
