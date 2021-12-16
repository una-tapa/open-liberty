/*******************************************************************************
 * Copyright (c) 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.jdbc.fat.krb5.containers;

import static com.ibm.ws.jdbc.fat.krb5.containers.KerberosContainer.KRB5_KDC;
import static com.ibm.ws.jdbc.fat.krb5.containers.KerberosContainer.KRB5_REALM;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.OracleContainer;
import org.testcontainers.utility.DockerImageName;

import componenttest.containers.SimpleLogConsumer;

public class OracleKerberosContainer extends OracleContainer {

    private static final Class<?> c = OracleKerberosContainer.class;

    // NOTE: If this is ever updated, don't forget to push to docker hub, but DO NOT overwrite existing versions
    //TODO update this image to be built on top of gvenzl/oracle-xe
    private static final String IMAGE_NAME_STRING = "kyleaure/oracle-18.4.0-expanded:1.0.full.krb5";
    private static final DockerImageName IMAGE_NAME = DockerImageName.parse(IMAGE_NAME_STRING).asCompatibleSubstituteFor("gvenzl/oracle-xe");

    public OracleKerberosContainer(Network network) {
        super(IMAGE_NAME);
        super.withPassword("oracle"); //Tell superclass the hardcoded password
        super.usingSid(); //Maintain current behavior of connecting with SID instead of pluggable database
        super.withNetwork(network);
        super.withLogConsumer(new SimpleLogConsumer(c, "oracle-krb5"));
    }

    @Override
    protected void configure() {
        withNetworkAliases("oracle");
        withCreateContainerCmdModifier(cmd -> {
            cmd.withHostName("oracle");
        });
        withEnv("KRB5_REALM", KRB5_REALM);
        withEnv("KRB5_KDC", KRB5_KDC);
        super.configure();
    }

    @Override
    public String getUsername() {
        return "system";
    }

    public String getKerberosUsername() {
        return "ORACLEUSR@" + KerberosContainer.KRB5_REALM;
    }

    @Override
    public OracleContainer withUsername(String username) {
        throw new UnsupportedOperationException("hardcoded setting, cannot change");
    }

    @Override
    public String getPassword() {
        return "oracle";
    }

    @Override
    public OracleContainer withPassword(String password) {
        throw new UnsupportedOperationException("hardcoded setting, cannot change");
    }

    @Override
    public String getDatabaseName() {
        return "XE";
    }

    @Override
    public OracleContainer withDatabaseName(String dbName) {
        throw new UnsupportedOperationException("hardcoded setting, cannot change");
    }
}
