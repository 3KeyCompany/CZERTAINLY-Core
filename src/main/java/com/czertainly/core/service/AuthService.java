package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.auth.UpdateUserRequestDto;
import com.czertainly.api.model.core.auth.AuthResourceDto;
import com.czertainly.api.model.core.auth.UserDetailDto;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.security.cert.CertificateException;
import java.util.List;

public interface AuthService {
    UserDetailDto getAuthProfile() throws NotFoundException, JsonProcessingException;

    List<AuthResourceDto> getAuthResources();

    UserDetailDto updateUserProfile(UpdateUserRequestDto request) throws NotFoundException, CertificateException;
}
