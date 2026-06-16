package com.example;

import java.io.IOException;

public class ExecController {
    public Process runCommand(String userInput) throws IOException {
        String command = "sh -c " + userInput;
        return Runtime.getRuntime().exec(command);
    }

    public String health() {
        return "ok";
    }
}

