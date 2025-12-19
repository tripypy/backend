package com.ssafy.jjtrip.domain.user.controller;

import com.ssafy.jjtrip.common.s3.exception.FileErrorCode;
import com.ssafy.jjtrip.common.s3.exception.FileException;
import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.user.dto.AiTravelAnalysisDto;
import com.ssafy.jjtrip.domain.user.dto.request.UpdateUserRequestDto;
import com.ssafy.jjtrip.domain.user.dto.response.ProfileImageUpdateResponseDto;
import com.ssafy.jjtrip.domain.user.dto.response.PublicUserProfileResponseDto;
import com.ssafy.jjtrip.domain.user.dto.response.UserSearchResponseDto;
import com.ssafy.jjtrip.domain.user.dto.response.UserProfileResponseDto;
import com.ssafy.jjtrip.domain.user.service.AiAnalysisService;
import com.ssafy.jjtrip.domain.user.service.UserService;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    private final AiAnalysisService aiAnalysisService;

    @GetMapping("/search")
    public ResponseEntity<List<UserSearchResponseDto>> searchUsers(@RequestParam("nickname") String nickname) {
        List<UserSearchResponseDto> users = userService.searchByNickname(nickname);
        return ResponseEntity.ok(users);
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfileResponseDto> getMyInfo(@AuthenticationPrincipal CustomUserDetails userDetails) {
        UserProfileResponseDto user = userService.getUserProfile(userDetails.getUser().getId());
        return ResponseEntity.ok(user);
    }
    
    @GetMapping("/{userId}/profile")
    public ResponseEntity<PublicUserProfileResponseDto> getUserProfile(@PathVariable("userId") Long userId) {
        PublicUserProfileResponseDto user = userService.getPublicUserProfile(userId);
        return ResponseEntity.ok(user);
    }

    @PatchMapping("/me")
    public ResponseEntity<Void> updateUserProfile(@AuthenticationPrincipal CustomUserDetails userDetails, @Valid @RequestBody UpdateUserRequestDto updateUserRequestDto) {
        userService.updateUserProfile(userDetails.getUser().getId(), updateUserRequestDto);
        return ResponseEntity.ok().build();
    }
    
    @PostMapping("/me/analysis")
    public ResponseEntity<AiTravelAnalysisDto> analyzeMyTravelStyle(@AuthenticationPrincipal CustomUserDetails userDetails) {
        AiTravelAnalysisDto result = aiAnalysisService.analyzeUserTravelStyle(userDetails.getUser().getId());
        return ResponseEntity.ok(result);
    }
    
    @GetMapping("/{userId}/friends")
    public ResponseEntity<List<PublicUserProfileResponseDto>> getUserFriends(@PathVariable("userId") Long userId) {
        List<PublicUserProfileResponseDto> friends = userService.getFriendsList(userId);
        return ResponseEntity.ok(friends);
    }

    @PostMapping("/profile-image")
    public ResponseEntity<ProfileImageUpdateResponseDto> updateProfileImage(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam("image") MultipartFile image) {

        if (image == null || image.isEmpty()) {
            throw new FileException(FileErrorCode.EMPTY_FILE);
        }

        ProfileImageUpdateResponseDto response = userService.updateProfileImage(userDetails.getUser().getId(), image);

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/profile-image")
    public ResponseEntity<Void> deleteProfileImage(@AuthenticationPrincipal CustomUserDetails userDetails) {
        userService.deleteProfileImage(userDetails.getUser().getId());
        return ResponseEntity.noContent().build();
    }
}
