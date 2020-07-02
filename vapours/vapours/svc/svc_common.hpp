/*
 * Copyright (c) 2018-2020 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

namespace nn::svc {

    /* TODO: C++ style handle? */
#ifdef ATMOSPHERE_IS_STRATOSPHERE
    using Handle = ::Handle;
#else
    using Handle = u32;
#endif

    enum {
        HandleWaitMask = (1u << 30),
    };

    constexpr inline size_t MaxWaitSynchronizationHandleCount = 0x40;

    constexpr inline s64 WaitInfinite = -1;

    enum PseudoHandle : Handle {
        CurrentThread  = 0xFFFF8000,
        CurrentProcess = 0xFFFF8001,
    };

    constexpr inline Handle InvalidHandle = Handle(0);

}
