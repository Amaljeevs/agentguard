package io.agentguard.consumer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        try (var context = SpringApplication.run(DemoApplication.class, args)) {
            // The command-line demo completes and the context closes automatically.
        }
    }
}
