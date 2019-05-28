package com.example.demo.conf.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {


    @RequestMapping("/index")
    public String index() {
        return "hello index";
    }

    @RequestMapping("/toLogin")
    public String toLogin() {
        return "toLogin";
    }
}
