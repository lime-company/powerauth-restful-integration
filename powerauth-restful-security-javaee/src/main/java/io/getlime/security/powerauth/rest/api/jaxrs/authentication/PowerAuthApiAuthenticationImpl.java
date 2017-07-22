/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.rest.api.jaxrs.authentication;

import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;

import java.io.Serializable;

/**
 * PowerAuth API authentication object used between intermediate server application (such as mobile 
 * banking API) and core systems (such as banking core).
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthApiAuthenticationImpl implements PowerAuthApiAuthentication, Serializable {

    private static final long serialVersionUID = -1270504081898389806L;

    private String activationId;
    private String userId;

    /**
     * Default constructor
     */
    public PowerAuthApiAuthenticationImpl() {
    }

    /**
     * Constructor for a new PowerAuthApiAuthenticationImpl
     * @param activationId Activation ID
     * @param userId User ID
     */
    public PowerAuthApiAuthenticationImpl(String activationId, String userId) {
        this.activationId = activationId;
        this.userId = userId;
    }

    /**
     * Get user ID
     * @return User ID
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID
     * @param userId User ID
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get activation ID
     * @return Activation ID
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

}
