/*********************************************************************
 *  This is part of DroidTracer
 *  (http://kuester.multics.org/DroidTracer).
 *
 *  Copyright (c) 2013-2015 by Jan-Christoph Küster
 *  <jckuester@gmail.com>
 *
 *  DroidTracer is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  DroidTracer is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with DroidTracer.  If not, see
 *  <http://www.gnu.org/licenses/>.
 ********************************************************************/

package org.multics.kuester.droidtracer;

import java.util.List;

public interface OnEventCallback {

    /**
     * Callback method that is triggered whenever a new system event has occurred.
     * Implement your analysis HERE.
     *
     * Note, an app must be intercepted to receive system events for it (@see startInterceptingApp
     * or interceptAllApps) or the according service needs to be added
     * to the whitelist (@see addServiceToWhitelist).
     *
     * @param time Unix time stamp (seconds since 1970).
     * @param uid Linux UID, which identifies an app.
     * @param service name of service called (e.g., com.android.internal.telephony.ISms).
     * @param method name of method called (e.g., sendText() if SMS was sent).
     * @param params unmarshalled method arguments.
     * @param paramTypes types of method arguments.
     * @param readErrorCount accumulated number of IPC read errors since start of DroidTracer
     */
    void onEvent(int time, int uid, String service, String method,
                        List<Object> params, String[] paramTypes, long readErrorCount);
}
