// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#[cfg(all(target_env = "ohos", feature = "hisysevent"))]
mod interface;

use code_generator::gen_hisysevent_func;

#[cfg(all(target_env = "ohos", feature = "hisysevent"))]
use crate::interface::*;

#[macro_export]
macro_rules! function {
    () => {{
        fn hook() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(hook);
        let off_set: usize = 6; // ::hook
        &name[..name.len() - off_set]
    }};
}

gen_hisysevent_func! {}
