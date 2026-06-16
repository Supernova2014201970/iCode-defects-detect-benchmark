package com.example;

import java.io.IOException;
import java.util.Set;

public class ExecController {
    private static final Set<String> ALLOWED = Set.of("date", "uptime");

    public Process runCommand(String userInput) throws IOException {
        if (!ALLOWED.contains(userInput)) {
            throw new IllegalArgumentException("unsupported command");
        }
        return new ProcessBuilder(userInput).start();
    }

    public String health() {
        return "ok";
    }
}

