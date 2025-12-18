package com.ssafy.jjtrip.domain.user.service;

import com.ssafy.jjtrip.common.mail.EmailService;
import com.ssafy.jjtrip.common.s3.S3Provider;
import com.ssafy.jjtrip.common.util.EmailMasker;
import com.ssafy.jjtrip.domain.auth.exception.AuthErrorCode;
import com.ssafy.jjtrip.domain.auth.exception.AuthException;
import com.ssafy.jjtrip.domain.trip.dto.TripDetailResponseDto;
import com.ssafy.jjtrip.domain.trip.dto.TripResponseDto;
import com.ssafy.jjtrip.domain.trip.entity.Trip;
import com.ssafy.jjtrip.domain.trip.entity.TripStatus;
import com.ssafy.jjtrip.domain.trip.mapper.TripMapper;
import com.ssafy.jjtrip.domain.triplog.dto.TripLogSummaryDto;
import com.ssafy.jjtrip.domain.triplog.mapper.TripLogMapper;
import com.ssafy.jjtrip.domain.user.dto.request.UpdateUserRequestDto;
import com.ssafy.jjtrip.domain.user.dto.response.ProfileImageUpdateResponseDto;
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
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final S3Provider s3Provider;
    private static final String DIR = "public/profile/";

    private final TripMapper tripMapper;
    private final TripLogMapper tripLogMapper;

    public UserProfileResponseDto getUserProfile(Long userId) {
        UserAndProfileDto userAndProfile = userMapper.findUserAndProfileById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));

        List<TripStatus> allStatuses = List.of(TripStatus.DRAFT, TripStatus.PLANNED, TripStatus.COMPLETED);
        List<Trip> allTrips = tripMapper.selectByUserIdAndStatuses(userId, allStatuses);

        List<TripResponseDto> tripOverviews = mapToTripResponseDtos(allTrips, userId);
        List<TripDetailResponseDto> completedTripDetails = mapToTripDetailResponseDtos(allTrips);
        List<TripLogSummaryDto> logs = tripLogMapper.findSummariesByUserId(userId);

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
                .friendsCount(userAndProfile.getFriendsCount())
                .tripOverviews(tripOverviews)
                .completedTripDetails(completedTripDetails)
                .logs(logs)
                .build();
    }

    public PublicUserProfileResponseDto getPublicUserProfile(Long userId) {
        UserAndProfileDto userAndProfile = userMapper.findUserAndProfileById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));

        List<TripStatus> publicStatuses = List.of(TripStatus.PLANNED, TripStatus.COMPLETED);
        List<Trip> publicTrips = tripMapper.selectByUserIdAndStatuses(userId, publicStatuses);

        List<TripResponseDto> tripOverviews = mapToTripResponseDtos(publicTrips, userId);
        List<TripDetailResponseDto> completedTripDetails = mapToTripDetailResponseDtos(publicTrips);
        List<TripLogSummaryDto> logs = tripLogMapper.findSummariesByUserId(userId);

        return PublicUserProfileResponseDto.builder()
                .id(userAndProfile.getId())
                .nickname(userAndProfile.getNickname())
                .profileImageUrl(userAndProfile.getProfileImageUrl())
                .bio(userAndProfile.getBio())
                .intro(userAndProfile.getIntro())
                .homeRegionId(userAndProfile.getHomeRegionId())
                .travelStyleSummary(userAndProfile.getTravelStyleSummary())
                .travelStyleId(userAndProfile.getTravelStyleId())
                .profileBannerUrl(userAndProfile.getProfileBannerUrl())
                .isProfilePublic(userAndProfile.getIsProfilePublic())
                .friendsCount(userAndProfile.getFriendsCount())
                .tripOverviews(tripOverviews)
                .completedTripDetails(completedTripDetails)
                .logs(logs)
                .build();
    }

    private List<TripResponseDto> mapToTripResponseDtos(List<Trip> trips, Long userId) {
        return trips.stream()
                .map(trip -> {
                    boolean isOwner = trip.getUserId().equals(userId);
                    int spots = tripMapper.countTripItemsByTripId(trip.getId());
                    List<String> tags = Collections.emptyList();
                    List<TripResponseDto.SpotPreviewDto> spotPreviews = tripMapper.selectSpotPreviewNamesByTripId(trip.getId())
                            .stream()
                            .map(TripResponseDto.SpotPreviewDto::new)
                            .collect(Collectors.toList());
                    return TripResponseDto.from(trip, isOwner, spots, tags, spotPreviews);
                })
                .collect(Collectors.toList());
    }

    private List<TripDetailResponseDto> mapToTripDetailResponseDtos(List<Trip> trips) {
        return trips.stream()
                .filter(trip -> trip.getStatus() == TripStatus.COMPLETED)
                .map(trip -> {
                    trip.setTripItems(tripMapper.selectItemsWithSpotsByTripId(trip.getId()));
                    return TripDetailResponseDto.from(trip);
                })
                .collect(Collectors.toList());
    }

    public List<PublicUserProfileResponseDto> getFriendsList(Long userId) {
        List<UserAndProfileDto> friends = userMapper.findFriendsByUserId(userId);
        return friends.stream()
                .map(friend -> PublicUserProfileResponseDto.builder()
                        .id(friend.getId())
                        .nickname(friend.getNickname())
                        .profileImageUrl(friend.getProfileImageUrl())
                        .bio(friend.getBio())
                        .build())
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
    public ProfileImageUpdateResponseDto updateProfileImage(Long userId, MultipartFile profileImage) {
        User user = userMapper.findById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));
        String oldImageUrl = user.getProfileImageUrl();

        String newImageUrl = s3Provider.upload(profileImage, DIR);

        userMapper.updateProfileImageUrl(userId, newImageUrl);

        if (StringUtils.hasText(oldImageUrl)) {
            s3Provider.deleteImage(oldImageUrl);
        }

        return new ProfileImageUpdateResponseDto(newImageUrl);
    }

    @Transactional
    public void deleteProfileImage(Long userId) {
        User user = userMapper.findById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.USER_NOT_FOUND));
        String imageUrl = user.getProfileImageUrl();

        if (StringUtils.hasText(imageUrl)) {
            s3Provider.deleteImage(imageUrl);
            userMapper.deleteProfileImageUrl(userId);
        }
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
