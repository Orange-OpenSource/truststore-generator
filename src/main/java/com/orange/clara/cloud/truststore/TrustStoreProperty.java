/*
 *
 *  * Copyright (C) 2015 Orange
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 *
 */

package com.orange.clara.cloud.truststore;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.security.cert.Certificate;
import java.util.List;

/**
 * Created by sbortolussi on 23/10/2015.
 */
@JsonAutoDetect(
        getterVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(
        ignoreUnknown = true
)
public class TrustStoreProperty {

    @JsonDeserialize(using = CertificateJsonDeserializer.class)
    @JsonProperty("certificates")
    private List<Certificate> certificates;

    public TrustStoreProperty() {
    }

    public TrustStoreProperty(List<Certificate> certificates) {
        setCertificates(certificates);
    }

    private void setCertificates(List<Certificate> certificates) {
        if (certificates == null || certificates.size() < 1)
            throw new IllegalArgumentException("Invalid truststore property. Should contain at least a certificate.");
        this.certificates = certificates;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    @Override
    public String toString() {
        return "TrustStoreProperty{" +
                "certificates=" + certificates +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TrustStoreProperty that = (TrustStoreProperty) o;

        return !(certificates != null ? !certificates.equals(that.certificates) : that.certificates != null);

    }

    @Override
    public int hashCode() {
        return certificates != null ? certificates.hashCode() : 0;
    }
}
