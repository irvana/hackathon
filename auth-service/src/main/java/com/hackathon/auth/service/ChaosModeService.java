package com.hackathon.auth.service;

import org.springframework.stereotype.Service;

@Service
public class ChaosModeService {

    private volatile boolean isChaosMode = false;

    public boolean isChaosMode() {
        return isChaosMode;
    }

    public void activate() {
        isChaosMode = true;
    }

    public void deactivate() {
        isChaosMode = false;
    }
}
