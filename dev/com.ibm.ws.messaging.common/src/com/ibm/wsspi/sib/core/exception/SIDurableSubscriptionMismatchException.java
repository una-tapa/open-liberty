/*******************************************************************************
 * Copyright (c) 2012 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/

package com.ibm.wsspi.sib.core.exception;

import com.ibm.websphere.sib.exception.SINotPossibleInCurrentStateException;

/**
 This exception is thrown by the createConsumerSessionForDurableSubscription 
 method if the parameters to the call do not match a subscription that exists 
 with the name supplied. It should not contain a linked exception. The recovery 
 action in this case is to delete the existing subscription and create a new 
 one.
 <p>
 This class has no security implications.
 */
public class SIDurableSubscriptionMismatchException
  extends SINotPossibleInCurrentStateException
{

  private static final long serialVersionUID = -2286296746508579860L;
  public SIDurableSubscriptionMismatchException(String msg)
  {
    super(msg);
  }

}
