/*
 * Copyright 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

use engine::common::lru_cache::LruCache;
use poet2_util;
use sawtooth_sdk::consensus::engine::*;

const WAIT_TIME_CACHE_SZ: usize = 1024;

#[derive(Debug)]
pub struct WaitTimeCache {
    wait_time_cache: LruCache<BlockId, u64>,
}

impl WaitTimeCache {
    pub fn new() -> Self {
        WaitTimeCache {
            wait_time_cache: LruCache::new(Some(WAIT_TIME_CACHE_SZ)),
        }
    }

    /// A wrapper method over get_wait_time_from() from util.
    /// This would cache the wait times in a LRU Cache.
    pub fn get_wait_time_for(&mut self, block: &Block) -> u64 {
        let wait_time: u64;
        // Introducing a flag to avoid borrowing mutably twice
        let mut to_update = false;
        match self.wait_time_cache.get(&block.block_id) {
            Some(time) => {
                wait_time = *time;
            }
            None => {
                let time = poet2_util::get_wait_time_from(block);
                wait_time = time;
                to_update = true;
            }
        };
        if to_update {
            self.wait_time_cache.set(block.block_id.clone(), wait_time);
        }
        wait_time
    }
}
