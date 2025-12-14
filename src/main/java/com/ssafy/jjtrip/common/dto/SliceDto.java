package com.ssafy.jjtrip.common.dto;

import java.util.List;

public record SliceDto<T>(
    List<T> content,
    Long nextCursor,
    boolean hasNext
) {
}
