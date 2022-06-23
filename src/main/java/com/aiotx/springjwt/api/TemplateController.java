package com.aiotx.springjwt.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = "/")
public class TemplateController {

    @GetMapping("dashboard")
    public String getDashboard() {
        return "dashboard";
    }
}
