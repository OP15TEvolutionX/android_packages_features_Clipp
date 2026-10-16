// Copyright (C) 2026 Evolution X
// SPDX-License-Identifier: Apache-2.0
package com.android.systemui.clipp

import android.content.Context
import com.android.systemui.CoreStartable
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Application
import com.android.systemui.settings.UserTracker
import dagger.Binds
import dagger.Module
import dagger.multibindings.ClassKey
import dagger.multibindings.IntoMap
import javax.inject.Inject

@SysUISingleton
class ClippStartable @Inject constructor(
    @Application private val context: Context,
    private val userTracker: UserTracker,
) : CoreStartable {
    private var engine: ClippEngine? = null
    // UserTracker holds weak callback references; keep this callback alive with the startable.
    private val userCallback = object : UserTracker.Callback {
        override fun onBeforeUserSwitching(newUser: Int) { engine?.close(); engine = null }
        override fun onUserChanged(newUser: Int, userContext: Context) { restart() }
    }
    private fun restart() {
        engine?.close()
        engine = ClippEngine(userTracker.userContext).also { it.start() }
    }
    override fun start() {
        userTracker.addCallback(userCallback, context.mainExecutor)
        restart()
    }
}

@Module
abstract class ClippModule {
    @Binds @IntoMap @ClassKey(ClippStartable::class)
    abstract fun bindClipp(impl: ClippStartable): CoreStartable
}
