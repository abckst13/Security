package com.security.project.auth.vo;


import lombok.Data;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;

@Data
public class Users {

    private String userId;
    private String password;
    private String userName;
    private String email;
    private String phoneNum;
    private String imgUrl;
    private  String refreshToken;
    private LocalDate createdAt;

    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void destroyRefreshToken() {
        this.refreshToken = null;
    }

    //== 패스워드 암호화 ==//
    public void encodePassword(PasswordEncoder passwordEncoder){
        this.password = passwordEncoder.encode(password);
    }
}
