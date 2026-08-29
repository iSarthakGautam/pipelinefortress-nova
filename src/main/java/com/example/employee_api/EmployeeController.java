package com.example.employee_api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class EmployeeController {

    @GetMapping("/api/employees")
    public List<Map<String, Object>> getEmployees() {

        return List.of(
            Map.of(
                "id", 1,
                "name", "Alice",
                "department", "Engineering"
            ),
            Map.of(
                "id", 2,
                "name", "Bob",
                "department", "Support"
            ),
            Map.of(
                "id", 3,
                "name", "Charlie",
                "department", "DevSecOps"
            )
        );
    }
}
