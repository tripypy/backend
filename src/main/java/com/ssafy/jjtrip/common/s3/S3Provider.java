package com.ssafy.jjtrip.common.s3;

import com.ssafy.jjtrip.common.s3.dto.PresignedUrlResponseDto;
import com.ssafy.jjtrip.common.s3.exception.FileErrorCode;
import com.ssafy.jjtrip.common.s3.exception.FileException;
import java.io.IOException;
import java.time.Duration;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

@Component
public class S3Provider {

    private static final String URL_SEPARATOR = "/";

    private final S3Client s3Client;
    private final S3Presigner s3Presigner;
    private final String bucketName;
    private final String baseUrl;

    public S3Provider(S3Client s3Client,
                      S3Presigner s3Presigner,
                      @Value("${spring.cloud.aws.s3.bucket}") String bucketName,
                      @Value("${file.base-url}") String baseUrl) {
        this.s3Client = s3Client;
        this.s3Presigner = s3Presigner;
        this.bucketName = bucketName;
        this.baseUrl = baseUrl;
    }

    public PresignedUrlResponseDto generatePresignedUrl(String prefix, String fileName) {
        String key = createKey(prefix, fileName);

        String contentType = determineContentType(fileName);

        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucketName)
                .key(key)
                .contentType(contentType)
                .acl("public-read")
                .build();

        PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                .signatureDuration(Duration.ofMinutes(10))
                .putObjectRequest(putObjectRequest)
                .build();

        String presignedUrl = s3Presigner.presignPutObject(presignRequest).url().toString();
        String url = baseUrl + "/" + key;
        
        return new PresignedUrlResponseDto(presignedUrl, url, key);
    }

    private String determineContentType(String fileName) {
        String ext = StringUtils.getFilenameExtension(fileName);
        if (ext == null) return "application/octet-stream";
        return switch (ext.toLowerCase()) {
            case "jpg", "jpeg" -> "image/jpeg";
            case "png" -> "image/png";
            case "gif" -> "image/gif";
            case "webp" -> "image/webp";
            default -> "application/octet-stream";
        };
    }

    public String upload(MultipartFile file, String prefix) {
        if (file.isEmpty()) {
            throw new FileException(FileErrorCode.EMPTY_FILE);
        }

        String key = createKey(prefix, file.getOriginalFilename());

        try {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .contentType(file.getContentType())
                    .contentLength(file.getSize())
                    .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromInputStream(file.getInputStream(), file.getSize()));
        } catch (IOException e) {
            throw new FileException(FileErrorCode.FILE_UPLOAD_FAILED);
        }

        return baseUrl + "/" + key;
    }

    public String upload(byte[] content, String originalFilename, String contentType, String prefix) {
        if (content == null || content.length == 0) {
            throw new FileException(FileErrorCode.EMPTY_FILE);
        }

        String key = createKey(prefix, originalFilename);

        try {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .contentType(contentType)
                    .contentLength((long) content.length)
                    .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromBytes(content));
        } catch (Exception e) {
            throw new FileException(FileErrorCode.FILE_UPLOAD_FAILED);
        }

        return baseUrl + "/" + key;
    }

    public void deleteImage(String imageUrl) {
        if (imageUrl == null || imageUrl.isEmpty() || !imageUrl.startsWith(baseUrl)) {
            return;
        }
        try {
            String key = extractKeyFromUrl(imageUrl);
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            s3Client.deleteObject(deleteObjectRequest);
        } catch (Exception e) {
            System.err.println("Failed to delete old S3 image: " + imageUrl + ". Error: " + e.getMessage());
        }
    }

    private String createKey(String prefix, String originalFilename) {
        String ext = StringUtils.getFilenameExtension(originalFilename);
        if (!StringUtils.hasText(ext)) {
            throw new FileException(FileErrorCode.INVALID_FILE_EXTENSION);
        }
        String uuid = UUID.randomUUID().toString();
        return prefix + uuid + "." + ext;
    }

    private String extractKeyFromUrl(String imageUrl) {
        return imageUrl.substring(baseUrl.length() + URL_SEPARATOR.length());
    }
}
