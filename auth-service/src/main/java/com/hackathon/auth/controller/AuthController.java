package com.hackathon.auth.controller;

import com.hackathon.auth.service.AuthValidationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthValidationService authValidationService;

    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate() {
        return ResponseEntity.ok(authValidationService.validate());
    }
}
