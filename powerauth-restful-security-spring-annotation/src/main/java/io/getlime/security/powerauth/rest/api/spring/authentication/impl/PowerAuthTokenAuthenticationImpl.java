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

import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthTokenAuthentication;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Implementation of the {@link PowerAuthTokenAuthentication} interface, with Spring Security objects.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthTokenAuthenticationImpl extends AbstractAuthenticationToken implements PowerAuthTokenAuthentication {

    /**
     * Token ID.
     */
    private String tokenId;

    /**
     * Token digest value.
     */
    private String tokenDigest;

    /**
     * Cryptographic nonce.
     */
    private String nonce;

    /**
     * Current timestamp.
     */
    private String timestamp;

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
    public PowerAuthTokenAuthenticationImpl() {
        super(null);
    }

    // Authentication Token Related methods

    @Override
    public Object getPrincipal() {
        return tokenId;
    }

    @Override
    public Object getCredentials() {
        return tokenDigest;
    }

    // Getters and setters for fields

    /**
     * Get token ID.
     * @return Token ID.
     */
    @Override
    public String getTokenId() {
        return tokenId;
    }

    /**
     * Set token ID.
     * @param tokenId Token ID.
     */
    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    /**
     * Get token digest.
     * @return Token digest.
     */
    @Override
    public String getTokenDigest() {
        return tokenDigest;
    }

    /**
     * Set token digest.
     * @param tokenDigest Token digest.
     */
    public void setTokenDigest(String tokenDigest) {
        this.tokenDigest = tokenDigest;
    }

    /**
     * Get token related nonce.
     * @return Nonce.
     */
    @Override
    public String getNonce() {
        return nonce;
    }

    /**
     * Set token related nonce.
     * @param nonce Nonce.
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * Get token creation timestamp.
     * @return Token timestamp.
     */
    @Override
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * Set token creation timestamp.
     * @param timestamp Token timestamp.
     */
    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Get PowerAuth protocol version.
     * @return PowerAuth protocol version.
     */
    @Override
    public String getVersion() {
        return version;
    }

    /**
     * Set PowerAuth protocol version.
     * @param version PowerAuth protocol version.
     */
    @Override
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Get parsed PowerAuth HTTP header.
     * @return PowerAuth HTTP header.
     */
    @Override
    public PowerAuthHttpHeader getHttpHeader() {
        return httpHeader;
    }

    /**
     * Set parsed PowerAuth HTTP header.
     * @param httpHeader PowerAuth HTTP header.
     */
    @Override
    public void setHttpHeader(PowerAuthHttpHeader httpHeader) {
        this.httpHeader = httpHeader;
    }
}
