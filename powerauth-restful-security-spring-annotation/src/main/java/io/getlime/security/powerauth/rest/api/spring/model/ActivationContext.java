/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.model;

import com.wultra.security.powerauth.client.v3.ActivationStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Class representing the activation context data. It maps detailed activation attributes
 * to a class that is supposed to be used by the developers in various scenarios.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ActivationContext {
    
    private String activationId;
    private String activationName;
    private final List<String> activationFlags;
    private ActivationStatus activationStatus;
    private String blockedReason;
    private long applicationId;
    private String userId;
    private long version;
    private Instant timestampCreated;
    private Instant timestampLastUsed;
    private Instant timestampLastChange;
    private String platform;
    private String deviceInfo;
    private String extras;

    public ActivationContext() {
        this.activationFlags = new ArrayList<>();
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation name.
     * @param activationName Activation name.
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Get activation name.
     * @return Activation name.
     */
    public String getActivationName() {
        return activationName;
    }

    /**
     * Get activation flags.
     * @return Activation flags.
     */
    public List<String> getActivationFlags() {
        return activationFlags;
    }

    /**
     * Set activation status.
     * @param activationStatus Activation status.
     */
    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    /**
     * Get activation status.
     * @return Activation status.
     */
    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    /**
     * Set blocked reason.
     * @param blockedReason Blocked reason.
     */
    public void setBlockedReason(String blockedReason) {
        this.blockedReason = blockedReason;
    }

    /**
     * Get blocked reason.
     * @return Blocked reason.
     */
    public String getBlockedReason() {
        return blockedReason;
    }

    /**
     * Set application ID.
     * @param applicationId Application ID.
     */
    public void setApplicationId(long applicationId) {
        this.applicationId = applicationId;
    }

    /**
     * Get application ID.
     * @return Application ID.
     */
    public long getApplicationId() {
        return applicationId;
    }

    /**
     * Set user ID.
     * @param userId User ID.
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get user ID.
     * @return User ID.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set version.
     * @param version Version.
     */
    public void setVersion(long version) {
        this.version = version;
    }

    /**
     * Get version.
     * @return Version.
     */
    public long getVersion() {
        return version;
    }

    /**
     * Set timestamp created.
     * @param timestampCreated Timestamp created.
     */
    public void setTimestampCreated(Instant timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get timestamp created.
     * @return Timestamp created.
     */
    public Instant getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set timestamp last used.
     * @param timestampLastUsed Timestamp last used.
     */
    public void setTimestampLastUsed(Instant timestampLastUsed) {
        this.timestampLastUsed = timestampLastUsed;
    }

    /**
     * Get timestamp last used.
     * @return Timestamp last used.
     */
    public Instant getTimestampLastUsed() {
        return timestampLastUsed;
    }

    /**
     * Set timestamp last change.
     * @param timestampLastChange Timestamp last change.
     */
    public void setTimestampLastChange(Instant timestampLastChange) {
        this.timestampLastChange = timestampLastChange;
    }

    /**
     * Get timestamp last change.
     * @return Timestamp last change.
     */
    public Instant getTimestampLastChange() {
        return timestampLastChange;
    }

    /**
     * Set platform.
     * @param platform Platform.
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Get platform.
     * @return Platform.
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Set device info.
     * @param deviceInfo Device info.
     */
    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    /**
     * Get device info.
     * @return Device info.
     */
    public String getDeviceInfo() {
        return deviceInfo;
    }

    /**
     * Set extras.
     * @param extras Extras.
     */
    public void setExtras(String extras) {
        this.extras = extras;
    }

    /**
     * Get extras.
     * @return Extras.
     */
    public String getExtras() {
        return extras;
    }
}
