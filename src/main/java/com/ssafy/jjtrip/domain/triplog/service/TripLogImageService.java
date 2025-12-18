package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.common.s3.S3Provider;
import com.ssafy.jjtrip.common.s3.dto.PresignedUrlResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.request.ImageUploadRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TripLogImageService {

    private final S3Provider s3Provider;
    private static final String TRIP_LOG_DIR = "triplog/";
    private static final String USER_DIR = "users/";


    public PresignedUrlResponseDto generatePresignedUrl(Long userId, ImageUploadRequestDto imageUploadRequest) {
        String dir = USER_DIR + userId + "/" + TRIP_LOG_DIR;
        return s3Provider.generatePresignedUrl(dir, imageUploadRequest.fileName());
    }
}
