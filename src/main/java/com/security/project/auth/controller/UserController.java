package com.security.project.auth.controller;

import com.security.project.auth.service.UserService;
import com.security.project.auth.vo.Users;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;

    @PostMapping("/join")
    public ResponseEntity<String> userJoin(@RequestBody Users userParams) throws Exception {
        String result = userService.userJoin(userParams);
        return ResponseEntity.ok(result);
    }
}
