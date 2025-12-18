package com.ssafy.jjtrip.domain.triplog.service;

import com.ssafy.jjtrip.common.s3.S3Provider;
import com.ssafy.jjtrip.common.s3.dto.PresignedUrlResponseDto;
import com.ssafy.jjtrip.domain.triplog.dto.ImageUploadRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TripLogImageService {

    private final S3Provider s3Provider;
    private static final String DIR = "public/triplog/";

    public PresignedUrlResponseDto generatePresignedUrl(ImageUploadRequestDto imageUploadRequest) {
        return s3Provider.generatePresignedUrl(DIR, imageUploadRequest.fileName());
    }
}
