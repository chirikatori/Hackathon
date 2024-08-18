package com.dqnt.backend.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ViewController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
