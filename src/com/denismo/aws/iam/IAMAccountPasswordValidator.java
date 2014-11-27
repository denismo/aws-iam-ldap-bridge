/*
 * Copyright (c) 2014 Denis Mikhalkin.
 *
 * This software is provided to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.  You may obtain a copy of the
 * License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.denismo.aws.iam;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.SystemDefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.*;

/**
 * User: Denis Mikhalkin
 * Date: 27/11/2014
 * Time: 6:48 PM
 */
public class IAMAccountPasswordValidator implements _IAMPasswordValidator {
    private static final Logger LOG = LoggerFactory.getLogger(IAMAccountPasswordValidator.class);
    @Override
    public boolean verifyIAMPassword(Entry user, String pw) throws LdapInvalidAttributeValueException, LdapAuthenticationException {
        try {
            LOG.debug("Verifying {} {} with accessKey <hidden> and secretKey <hidden>",
                    "user", user.get("uid").getString());
            HttpClient client = new SystemDefaultHttpClient();
            HttpPost post = new HttpPost("https://signin.aws.amazon.com/oauth");
            post.setHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.65 Safari/537.36");
            post.setHeader("Referer", "https://signin.aws.amazon.com/oauth");
            List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
            urlParameters.add(new BasicNameValuePair("client_id", "arn:aws:iam::015428540659:user/homepage"));
            urlParameters.add(new BasicNameValuePair("isIAMUser", "1"));
            urlParameters.add(new BasicNameValuePair("account", user.get("accountNumber").getString()));
            urlParameters.add(new BasicNameValuePair("username", user.get("uid").getString()));
            urlParameters.add(new BasicNameValuePair("password", pw));
            urlParameters.add(new BasicNameValuePair("Action", "login"));
            urlParameters.add(new BasicNameValuePair("redirect_uri", "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true"));
            urlParameters.add(new BasicNameValuePair("forceMobileApp", ""));
            urlParameters.add(new BasicNameValuePair("forceMobileLayout", ""));
            urlParameters.add(new BasicNameValuePair("mfaLoginFailure", ""));
            urlParameters.add(new BasicNameValuePair("RemainingExpiryPeriod", ""));
            urlParameters.add(new BasicNameValuePair("mfacode", ""));
            urlParameters.add(new BasicNameValuePair("next_mfacode", ""));
            post.setEntity(new UrlEncodedFormEntity(urlParameters, Charset.forName("UTF-8")));

            HttpResponse response = client.execute(post);
            return containsHeaders(response, "aws-account-alias", "aws-creds");
        } catch (IOException e) {
            LOG.error("Exception validating password for " + user.get("uid").getString(), e);
            return false;
        } catch (RuntimeException t) {
            LOG.error("Exception validating password for " + user.get("uid").getString(), t);
            throw t;
        }
    }

    private boolean containsHeaders(HttpResponse response, String... headers) {
        Header[] headerList = response.getHeaders("Set-Cookie");
        Set<String> lookup = new HashSet<String>(Arrays.asList(headers));
        for (Header header : headerList) {
            String value = header.getValue();
            if (!value.contains("=")) continue;
            String[] parts = value.split("=");
            if (parts.length < 2) continue;
            lookup.remove(parts[0]);
        }
        return lookup.isEmpty();
    }
}
