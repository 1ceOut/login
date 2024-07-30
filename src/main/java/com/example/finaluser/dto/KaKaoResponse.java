package com.example.finaluser.dto;

import java.util.Map;

public class KaKaoResponse implements OAuth2Response{

    private Map<String, Object> getId;
    private Map<String, Object> attribute;
    private Map<String, Object> profile;

    public KaKaoResponse(Map<String, Object> attribute) {
        this.getId = attribute;
        this.attribute = (Map<String, Object>) attribute.get("kakao_account");
        this.profile = (Map<String, Object>) attribute.get("properties");

    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getProviderId() {
        return getId.get("id").toString();
    }

    @Override
    public String getEmail() {
        return attribute.get("email").toString();
    }

    @Override
    public String getName() {
        return profile.get("nickname").toString();
    }

    public String getProfile() {
        return profile.get("profile_image").toString();
    }
}
