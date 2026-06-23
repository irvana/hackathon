package com.hackathon.auth.controller;

import com.hackathon.auth.service.ChaosModeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/chaos")
@RequiredArgsConstructor
public class ChaosController {

    private final ChaosModeService chaosModeService;

    @PostMapping("/activate")
    public ResponseEntity<Map<String, Object>> activate() {
        chaosModeService.activate();
        return ResponseEntity.ok(Map.of(
                "chaosMode", true,
                "message", "Chaos mode activated"
        ));
    }

    @PostMapping("/deactivate")
    public ResponseEntity<Map<String, Object>> deactivate() {
        chaosModeService.deactivate();
        return ResponseEntity.ok(Map.of(
                "chaosMode", false,
                "message", "Chaos mode deactivated"
        ));
    }
}
