package com.ssafy.jjtrip.domain.user.controller;

import com.ssafy.jjtrip.common.s3.exception.FileErrorCode;
import com.ssafy.jjtrip.common.s3.exception.FileException;
import com.ssafy.jjtrip.common.security.CustomUserDetails;
import com.ssafy.jjtrip.domain.user.dto.response.ProfileImageUpdateResponseDto;
import com.ssafy.jjtrip.domain.user.dto.response.UserProfileResponseDto;
import com.ssafy.jjtrip.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

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
}
