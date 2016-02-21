/*********************************************************************
 * This is part of DroidTracer
 * (http://kuester.multics.org/DroidTracer).
 * <p/>
 * Copyright (c) 2013-2015 by Jan-Christoph Küster
 * <jckuester@gmail.com>
 * <p/>
 * DroidTracer is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 2 of the
 * License, or (at your option) any later version.
 * <p/>
 * DroidTracer is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with DroidTracer.  If not, see
 * <http://www.gnu.org/licenses/>.
 ********************************************************************/

package org.multics.kuester.droidtracer;

import java.util.List;

public interface OnEventCallback {

    /**
     * Callback method that is triggered whenever a new system event has occurred.
     * <p/>
     * Implement your analysis HERE.
     * Note that to receive events about an app, it must be traced via
     * {@link DroidTracerService#startTracingApp} or {@link DroidTracerService#setLowestUidTraced}.
     * Events are also received about a service that has been whitelisted via
     * {@link DroidTracerService#addInterfaceToWhitelist}.
     *
     * @param time          the Unix time stamp (seconds since 1970)
     * @param uid           the Linux UID that uniquely identifies an app
     * @param interfaceName the IBinder interface name that identifies a service
     *                      (e.g., com.android.internal.telephony.ISms), or
     *                      "syscall" if the event ressambles an intercepted system call.
     * @param method        the name of the method called (e.g., sendText() if SMS was sent), or
     *                      system call function name (e.g., sys_open)
     * @param params        the unmarshalled method arguments
     * @param paramTypes    the Java types of method arguments
     * @param eventCounter the accumulated number of events sent since loading of the kernel module
     */
    void onEvent(int time, int uid, String interfaceName, String method,
                 List<?> params, String[] paramTypes, long eventCounter);
}