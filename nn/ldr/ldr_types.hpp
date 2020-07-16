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
#include <vapours.hpp>
#include <nn/ncm/ncm_program_location.hpp>

namespace nn::ldr {

    /* General types. */
    struct ProgramInfo {
        u8 main_thread_priority;
        u8 default_cpu_id;
        u16 flags;
        u32 main_thread_stack_size;
        ncm::ProgramId program_id;
        u32 acid_sac_size;
        u32 aci_sac_size;
        u32 acid_fac_size;
        u32 aci_fah_size;
        u8 ac_buffer[0x3E0];
    };
    static_assert(util::is_pod<ProgramInfo>::value && sizeof(ProgramInfo) == 0x400, "ProgramInfo definition!");

    enum ProgramInfoFlag {
        ProgramInfoFlag_SystemModule        = (0 << 0),
        ProgramInfoFlag_Application         = (1 << 0),
        ProgramInfoFlag_Applet              = (2 << 0),
        ProgramInfoFlag_InvalidType         = (3 << 0),
        ProgramInfoFlag_ApplicationTypeMask = (3 << 0),

        ProgramInfoFlag_AllowDebug = (1 << 2),
    };

    enum CreateProcessFlag {
        CreateProcessFlag_EnableDebug = (1 << 0),
        CreateProcessFlag_DisableAslr = (1 << 1),
    };

    struct ProgramArguments {
        u32 allocated_size;
        u32 arguments_size;
        u8  reserved[0x18];
        u8  arguments[];
    };
    static_assert(sizeof(ProgramArguments) == 0x20, "ProgramArguments definition!");

    struct PinId {
        u64 value;
    };

}
