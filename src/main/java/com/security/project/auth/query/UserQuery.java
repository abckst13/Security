package com.security.project.auth.query;

import com.security.project.auth.vo.Users;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.startup.Catalina;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.aggregation.Aggregation;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserQuery {

    private final MongoTemplate mongoTemplate;
    private final PasswordEncoder passwordEncoder;

    @Value("${collection.user-collection}")
    private String userCollection;

    public Users userFind(Users users) {
        Query query = new Query();
        query = Query.query(Criteria.where("userId").is(users.getUserId()));
        return mongoTemplate.findOne(query, Users.class, userCollection);
    }

    public Users userInfo(String userId) {
        Query query = new Query();
        query = Query.query(Criteria.where("userId").is(userId));
        return mongoTemplate.findOne(query, Users.class, userCollection);
    }

    public void userJoin(Users users) {
        users.setPassword(passwordEncoder.encode(users.getPassword())); // security PasswordEncoder 사용해 암호화
        mongoTemplate.save(users, userCollection);
    }

    public Users findByRefreshTokenUserInfo(String refreshToken) {
        Query query = new Query();
        query = Query.query(Criteria.where("refreshToken").is(refreshToken));
        return mongoTemplate.findOne(query,Users.class,userCollection);
    }
}
