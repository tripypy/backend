package com.ssafy.jjtrip.domain.user.controller;

import com.ssafy.jjtrip.common.s3.exception.FileErrorCode;
import com.ssafy.jjtrip.common.s3.exception.FileException;
import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.user.dto.request.UpdateUserRequestDto;
import com.ssafy.jjtrip.domain.user.dto.response.ProfileImageUpdateResponseDto;
import com.ssafy.jjtrip.domain.user.dto.response.UserProfileResponseDto;
import com.ssafy.jjtrip.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<UserProfileResponseDto> getMyInfo(@AuthenticationPrincipal CustomUserDetails userDetails) {
        UserProfileResponseDto user = userService.getUserProfile(userDetails.getUser().getId());
        return ResponseEntity.ok(user);
    }
    
    @GetMapping("/{userId}/profile")
    public ResponseEntity<UserProfileResponseDto> getUserProfile(@PathVariable("userId") Long userId) {
        UserProfileResponseDto user = userService.getUserProfile(userId);
        return ResponseEntity.ok(user);
    }

    @PatchMapping("/me")
    public ResponseEntity<Void> updateUserProfile(@AuthenticationPrincipal CustomUserDetails userDetails, @RequestBody UpdateUserRequestDto updateUserRequestDto) {
        userService.updateUserProfile(userDetails.getUser().getId(), updateUserRequestDto);
        return ResponseEntity.ok().build();
    }
    
    @GetMapping("/me/friends")
    public ResponseEntity<List<UserProfileResponseDto>> getMyFriends(@AuthenticationPrincipal CustomUserDetails userDetails) {
        List<UserProfileResponseDto> friends = userService.getFriendsList(userDetails.getUser().getId());
        return ResponseEntity.ok(friends);
    }

    @PostMapping("/profile-image")
    public ResponseEntity<ProfileImageUpdateResponseDto> updateUserProfileImage(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam("image") MultipartFile image) {

        if (image == null || image.isEmpty()) {
            throw new FileException(FileErrorCode.EMPTY_FILE);
        }

        String newImageUrl = userService.updateUserProfileImage(userDetails.getUser().getId(), image);

        ProfileImageUpdateResponseDto response = new ProfileImageUpdateResponseDto(newImageUrl);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/profile-image")
    public ResponseEntity<Void> deleteUserProfileImage(@AuthenticationPrincipal CustomUserDetails userDetails) {
        userService.deleteUserProfileImage(userDetails.getUser().getId());
        return ResponseEntity.noContent().build();
    }
}
