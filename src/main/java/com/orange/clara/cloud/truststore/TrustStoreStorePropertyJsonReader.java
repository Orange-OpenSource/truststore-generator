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

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Created by sbortolussi on 27/10/2015.
 */
public class TrustStoreStorePropertyJsonReader implements TrustStorePropertyReader<String> {


    @Override
    public TrustStoreProperty read(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(json, TrustStoreProperty.class);

        } catch (Exception e) {
            String message = String
                    .format("Invalid truststore property.");
            throw new IllegalStateException(message, e);
        }

    }


}
