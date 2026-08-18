package com.example.AuthenticationBackedJava.Authentication.dto;

import lombok.*;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Getter
@Setter
public class ErrorResponseDTO {
    private int status;
    private String message;
    private LocalDateTime timestamp;
    private String path;

    public ErrorResponseDTO(int status, String message, LocalDateTime timestamp, String path) {
        this.status = status;
        this.message = message;
        this.timestamp = timestamp;
        this.path = path;
        this.validationErrors = validationErrors;
    }

    private Map<String, String> validationErrors;
}
