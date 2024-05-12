package com.security.project.handler.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@Getter
public enum ExceptionHandler {
    // enum을 통해 미리 값을 설정한다.
    // DUPLICATED_USER_NAME의 이름을 가진 에러에 (에러상태 Conflict(409) 출력, 에러메세지)의 값을 넣은 구조만 받는다.
    DUPLICATED_USER_NAME(HttpStatus.CONFLICT, "User name is duplicated.");

    private HttpStatus status;
    private String message;
}
