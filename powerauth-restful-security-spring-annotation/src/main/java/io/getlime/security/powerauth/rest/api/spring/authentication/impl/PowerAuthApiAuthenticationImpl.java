/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.getlime.security.powerauth.rest.api.spring.authentication.impl;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * PowerAuth API authentication object used between intermediate server application (such as mobile 
 * banking API) and core systems (such as banking core).
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthApiAuthenticationImpl extends AbstractAuthenticationToken implements PowerAuthApiAuthentication, Serializable {

    private static final long serialVersionUID = -3790516505615465445L;

    /**
     * Activation ID.
     */
    private String activationId;

    /**
     * User ID.
     */
    private String userId;

    /**
     * Application ID.
     */
    private Long applicationId;

    /**
     * List of application roles.
     */
    private List<String> applicationRoles;

    /**
     * List of activation flags.
     */
    private List<String> activationFlags;

    /**
     * Signature type, representing used authentication factor.
     */
    private PowerAuthSignatureTypes factors;

    /**
     * Signature version.
     */
    private String version;

    /**
     * Reference to the original HTTP header.
     */
    private PowerAuthHttpHeader httpHeader;

    /**
     * Default constructor
     */
    public PowerAuthApiAuthenticationImpl() {
        super(null);
    }

    /**
     * Constructor for a new PowerAuthApiAuthenticationImpl.
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @param factors Authentication factors.
     */
    public PowerAuthApiAuthenticationImpl(String activationId, String userId, Long applicationId, List<String> applicationRoles, PowerAuthSignatureTypes factors) {
        super(null);
        this.activationId = activationId;
        this.userId = userId;
        this.applicationId = applicationId;
        this.factors = factors;
    }

    @Override
    public String getName() {
        return userId;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> authorities = new ArrayList<>(1);
        authorities.add(new SimpleGrantedAuthority("USER"));
        return Collections.unmodifiableList(authorities);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.activationId;
    }

    @Override
    public String getUserId() {
        return userId;
    }

    @Override
    public void setUserId(String userId) {
        this.userId = userId;
    }

    @Override
    public String getActivationId() {
        return activationId;
    }

    @Override
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    @Override
    public Long getApplicationId() {
        return applicationId;
    }

    @Override
    public void setApplicationId(Long id) {
        this.applicationId = id;
    }

    @Override
    public List<String> getApplicationRoles() {
        return applicationRoles;
    }

    @Override
    public void setApplicationRoles(List<String> applicationRoles) {
        this.applicationRoles = applicationRoles;
    }

    @Override
    public List<String> getActivationFlags() {
        return activationFlags;
    }

    @Override
    public void setActivationFlags(List<String> activationFlags) {
        this.activationFlags = activationFlags;
    }


    @Override
    public PowerAuthSignatureTypes getSignatureFactors() {
        return factors;
    }

    @Override
    public void setSignatureFactors(PowerAuthSignatureTypes factors) {
        this.factors = factors;
    }

    @Override
    public String getVersion() {
        return version;
    }

    @Override
    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public PowerAuthHttpHeader getHttpHeader() {
        return httpHeader;
    }

    @Override
    public void setHttpHeader(PowerAuthHttpHeader httpHeader) {
        this.httpHeader = httpHeader;
    }
}
