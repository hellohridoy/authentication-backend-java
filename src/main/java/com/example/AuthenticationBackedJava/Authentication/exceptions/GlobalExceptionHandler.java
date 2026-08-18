package com.example.AuthenticationBackedJava.Authentication.exceptions;

import com.example.AuthenticationBackedJava.Authentication.dto.ErrorResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponseDTO> handleResourceNotFoundException(
        ResourceNotFoundException ex, WebRequest request) {

        ErrorResponseDTO ErrorResponseDTO = new ErrorResponseDTO(
            HttpStatus.NOT_FOUND.value(),
            ex.getMessage(),
            LocalDateTime.now(),
            request.getDescription(false)
        );

        return new ResponseEntity<>(ErrorResponseDTO, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponseDTO> handleBadCredentialsException(
        BadCredentialsException ex, WebRequest request) {

        ErrorResponseDTO ErrorResponseDTO = new ErrorResponseDTO(
            HttpStatus.UNAUTHORIZED.value(),
            "Invalid email or password",
            LocalDateTime.now(),
            request.getDescription(false)
        );

        return new ResponseEntity<>(ErrorResponseDTO, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponseDTO> handleUsernameNotFoundException(
        UsernameNotFoundException ex, WebRequest request) {

        ErrorResponseDTO ErrorResponseDTO = new ErrorResponseDTO(
            HttpStatus.NOT_FOUND.value(),
            ex.getMessage(),
            LocalDateTime.now(),
            request.getDescription(false)
        );

        return new ResponseEntity<>(ErrorResponseDTO, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDTO> handleValidationExceptions(
        MethodArgumentNotValidException ex, WebRequest request) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponseDTO ErrorResponseDTO = new ErrorResponseDTO(
            HttpStatus.BAD_REQUEST.value(),
            "Validation failed",
            LocalDateTime.now(),
            request.getDescription(false)
        );
        ErrorResponseDTO.setValidationErrors(errors);

        return new ResponseEntity<>(ErrorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponseDTO> handleIllegalArgumentException(
        IllegalArgumentException ex, WebRequest request) {

        ErrorResponseDTO ErrorResponseDTO = new ErrorResponseDTO(
            HttpStatus.BAD_REQUEST.value(),
            ex.getMessage(),
            LocalDateTime.now(),
            request.getDescription(false)
        );

        return new ResponseEntity<>(ErrorResponseDTO, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDTO> handleGlobalException(
        Exception ex, WebRequest request) {

        ex.printStackTrace();

        ErrorResponseDTO ErrorResponseDTO = new ErrorResponseDTO(
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            "An unexpected error occurred",
            LocalDateTime.now(),
            request.getDescription(false)
        );

        return new ResponseEntity<>(ErrorResponseDTO, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
