package com.example.finaluser.dto;


public interface OAuth2Response {

    //제공자 (Ex. naver, google, ...)
    String getProvider();

    //제공자에서 발금해주는 아이디(번호)
    String getProviderId();

    //이메일
    String getEmail();

    //사용자 실명
    String getName();


}
