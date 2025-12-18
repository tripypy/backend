package com.ssafy.jjtrip.domain.user.controller;

import com.ssafy.jjtrip.common.s3.exception.FileErrorCode;
import com.ssafy.jjtrip.common.s3.exception.FileException;
import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.user.dto.request.UpdateUserRequestDto;
import com.ssafy.jjtrip.domain.user.dto.response.PublicUserProfileResponseDto;
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
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

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
    public ResponseEntity<Void> updateUserProfile(@AuthenticationPrincipal CustomUserDetails userDetails, @RequestBody UpdateUserRequestDto updateUserRequestDto) {
        userService.updateUserProfile(userDetails.getUser().getId(), updateUserRequestDto);
        return ResponseEntity.ok().build();
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
