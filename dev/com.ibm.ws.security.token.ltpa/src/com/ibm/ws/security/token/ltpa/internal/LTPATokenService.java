/*******************************************************************************
 * Copyright (c) 2011, 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.token.ltpa.internal;

import java.util.HashMap;
import java.util.Map;

import org.osgi.service.component.ComponentContext;

import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenCreationFailedException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.security.token.TokenService;
import com.ibm.ws.security.token.ltpa.LTPAConfiguration;
import com.ibm.ws.security.token.ltpa.LTPAKeyInfoManager;
import com.ibm.wsspi.security.ltpa.Token;
import com.ibm.wsspi.security.ltpa.TokenFactory;

/**
 *
 */
public class LTPATokenService implements TokenService {
    private volatile LTPAConfiguration ltpaConfig;

    protected void setLtpaConfig(LTPAConfiguration ltpaConfig) {
        this.ltpaConfig = ltpaConfig;
    }

    protected void unsetLtpaConfig(LTPAConfiguration ltpaConfig) {
        if (this.ltpaConfig == ltpaConfig) {
            ltpaConfig = null;
        }
    }

    protected void activate(ComponentContext context) {
    }

    protected void deactivate(ComponentContext context) {
    }

    private Map<String, Object> createTokenFactoryMap() {
        //LTPAKeyInfoManager keyInfoManager = config.getLTPAKeyInfoManager();
        LTPAKeyInfoManager keyInfoManager = ltpaConfig.getLTPAKeyInfoManager();
        LTPAPrivateKey ltpaPrivateKey = new LTPAPrivateKey(keyInfoManager.getPrivateKey(ltpaConfig.getKeyFile()));
        LTPAPublicKey ltpaPublicKey = new LTPAPublicKey(keyInfoManager.getPublicKey(ltpaConfig.getKeyFile()));
        byte[] sharedKey = keyInfoManager.getSecretKey(ltpaConfig.getKeyFile());

        Map<String, Object> tokenFactoryMap = new HashMap<String, Object>();
        tokenFactoryMap.put(LTPAConstants.EXPIRATION, ltpaConfig.getTokenExpiration());
        tokenFactoryMap.put(LTPAConstants.SECRET_KEY, sharedKey);
        tokenFactoryMap.put(LTPAConstants.PUBLIC_KEY, ltpaPublicKey);
        tokenFactoryMap.put(LTPAConstants.PRIVATE_KEY, ltpaPrivateKey);
        return tokenFactoryMap;
    }

    private TokenFactory getTokenFactory() {

        TokenFactory tokenFactory = null;
        tokenFactory = ltpaConfig.getTokenFactory();
        if (tokenFactory != null) {
            return ltpaConfig.getTokenFactory();
        } else {
            Map<String, Object> tokenFactoryMap = createTokenFactoryMap();
            tokenFactory = new LTPAToken2Factory();
            tokenFactory.initialize(tokenFactoryMap);
        }
        return tokenFactory;
    }

    private void delayedInit() {
        System.out.println("DEBUG: Delayed TokenFactory Initialization");
        ltpaConfig.setTokenFactory(getTokenFactory());
    }

    /**
     * {@inheritDoc}
     *
     * @throws TokenCreationFailedException
     */
    @Override
    public Token createToken(Map<String, Object> tokenData) throws TokenCreationFailedException {
        delayedInit();
        TokenFactory tokenFactory = ltpaConfig.getTokenFactory();
        return tokenFactory.createToken(tokenData);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Token recreateTokenFromBytes(byte[] tokenBytes) throws InvalidTokenException, TokenExpiredException {
        TokenFactory tokenFactory = ltpaConfig.getTokenFactory();
        Token token = tokenFactory.validateTokenBytes(tokenBytes);
        validateRecreatedToken(token);
        return token;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Token recreateTokenFromBytes(byte[] tokenBytes, String... removeAttributes) throws InvalidTokenException, TokenExpiredException {
        TokenFactory tokenFactory = ltpaConfig.getTokenFactory();
        Token token = tokenFactory.validateTokenBytes(tokenBytes, removeAttributes);
        return token;
    }

    private void validateRecreatedToken(Token token) throws InvalidTokenException, TokenExpiredException {
        if (token != null && token.isValid()) {
            return;
        }
    }
}
