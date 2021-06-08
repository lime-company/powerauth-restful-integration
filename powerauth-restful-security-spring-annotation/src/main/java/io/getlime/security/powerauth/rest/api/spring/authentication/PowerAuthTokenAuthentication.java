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
package io.getlime.security.powerauth.rest.api.spring.authentication;

import io.getlime.security.powerauth.http.PowerAuthHttpHeader;

/**
 * Interface for authentication objects used for simple token-based authentication. This object mirrors
 * data that are transmitted in "X-PowerAuth-Token" header.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface PowerAuthTokenAuthentication extends PowerAuthAuthentication {

    /**
     * Get token identifier.
     * @return Token identifier.
     */
    String getTokenId();

    /**
     * Get token digest.
     * @return Token digest.
     */
    String getTokenDigest();

    /**
     * Get token specific nonce.
     * @return Nonce.
     */
    String getNonce();

    /**
     * Get token creation timestamp.
     * @return Timestamp.
     */
    String getTimestamp();

    /**
     * Set token identifier.
     * @param tokenId Token identifier.
     */
    void setTokenId(String tokenId);

    /**
     * Set token digest.
     * @param tokenDigest Token digest.
     */
    void setTokenDigest(String tokenDigest);

    /**
     * Set token specific nonce.
     * @param nonce Nonce.
     */
    void setNonce(String nonce);

    /**
     * Set token creation timestamp.
     * @param timestamp Timestamp.
     */
    void setTimestamp(String timestamp);

    /**
     * Get PowerAuth protocol version.
     * @return PowerAuth protocol version.
     */
    String getVersion();

    /**
     * Set PowerAuth protocol version.
     * @param version PowerAuth protocol version.
     */
    void setVersion(String version);

    /**
     * Get parsed PowerAuth HTTP header.
     * @return PowerAuth HTTP header.
     */
    PowerAuthHttpHeader getHttpHeader();

    /**
     * Set parsed PowerAuth HTTP header.
     * @param httpHeader PowerAuth HTTP header.
     */
    void setHttpHeader(PowerAuthHttpHeader httpHeader);
}
