// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::{Arc, Mutex, RwLock};

use util::byte_code::ByteCode;

use crate::errors::{ErrorKind, Result, ResultExt};
use crate::region::FlatView;
use crate::{
    AddressRange, FlatRange, GuestAddress, Listener, ListenerReqType, Region, RegionIoEventFd,
    RegionType,
};

/// Address Space of memory.
#[derive(Clone)]
pub struct AddressSpace {
    /// Root Region of this AddressSpace.
    root: Region,
    /// Flat_view is the output of rendering all regions in parent address-space,
    /// every time the topology changed (add/delete region), flat_view would be updated.
    flat_view: Arc<RwLock<FlatView>>,
    /// The triggered call-backs when flat_view changed.
    listeners: Arc<Mutex<Vec<Box<dyn Listener>>>>,
    /// The vector buffer would help in comparison stage of topology update.
    ioeventfds: Arc<Mutex<Vec<RegionIoEventFd>>>,
}

impl AddressSpace {
    /// Create a new `AddressSpace` according to the given root region.
    ///
    /// # Arguments
    ///
    /// * `root` - Root region of address space.
    pub fn new(root: Region) -> Result<Arc<AddressSpace>> {
        let space = Arc::new(AddressSpace {
            root: root.clone(),
            flat_view: Arc::new(RwLock::new(FlatView::default())),
            listeners: Arc::new(Mutex::new(Vec::new())),
            ioeventfds: Arc::new(Mutex::new(Vec::new())),
        });

        root.set_belonged_address_space(&space);
        if !space.root.subregions().is_empty() {
            space.update_topology()?;
        }

        Ok(space)
    }

    /// Get the copy of the root of AddressSpace.
    pub fn root(&self) -> &Region {
        &self.root
    }

    /// Register the listener to the `AddressSpace`.
    ///
    /// # Arguments
    ///
    /// * `listener` - Provided methods for Listener.
    ///
    /// # Errors
    ///
    /// Return Error if fail to call `listener`.
    pub fn register_listener(&self, listener: Box<dyn Listener>) -> Result<()> {
        for fr in self.flat_view.read().unwrap().0.iter() {
            listener
                .handle_request(Some(&fr), None, ListenerReqType::AddRegion)
                .chain_err(|| "Failed to call listener")?;
        }

        let mut idx = 0;
        let mut mls = self.listeners.lock().unwrap();
        while idx < mls.len() {
            let ml = mls.get(idx).unwrap();
            if ml.priority() >= listener.priority() {
                break;
            }
            idx += 1;
        }
        mls.insert(idx, listener);
        Ok(())
    }

    /// Call listener to deal with the request.
    ///
    /// # Arguments
    ///
    /// * `flat_range` - Available when operating `Region`.
    /// * `evtfd` - Available when operating `Ioeventfd`.
    /// * `req_type` - One selection of how to operate the `Region` or `Ioeventfd`.
    ///
    /// # Errors
    ///
    /// Return Error if fail to call listener.
    fn call_listeners(
        &self,
        flat_range: Option<&FlatRange>,
        evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> Result<()> {
        let listeners = self.listeners.lock().unwrap();
        match req_type {
            ListenerReqType::DeleteRegion | ListenerReqType::AddIoeventfd => {
                listeners.iter().rev().try_for_each(|ml| {
                    ml.handle_request(flat_range, evtfd, req_type)
                        .chain_err(|| "Failed to call listener")
                })
            }
            _ => listeners.iter().try_for_each(|ml| {
                ml.handle_request(flat_range, evtfd, req_type)
                    .chain_err(|| "Failed to call listener")
            }),
        }
    }

    /// Update the topology pass.
    ///
    /// # Arguments
    ///
    /// * `old_view` - Old flatview.
    /// * `new_view` - New flatview.
    /// * `is_add` - Add `new_view` if `true` otherwise replace the `old_view` with `new_view`.
    fn update_topology_pass(
        &self,
        old_view: &FlatView,
        new_view: &FlatView,
        is_add: bool,
    ) -> Result<()> {
        let old_ranges = &old_view.0;
        let new_ranges = &new_view.0;
        let mut old_idx = 0_usize;
        let mut new_idx = 0_usize;

        while old_idx < old_ranges.len() || new_idx < new_ranges.len() {
            let old_range = old_ranges.get(old_idx);
            let new_range = new_ranges.get(new_idx);

            if let Some(old_r) = old_range {
                if let Some(new_r) = new_range {
                    if old_r.addr_range == new_r.addr_range {
                        old_idx += 1;
                        new_idx += 1;
                        continue;
                    } else if old_r.addr_range.base < new_r.addr_range.base
                        || (old_r.addr_range.base == new_r.addr_range.base
                            && old_r.addr_range.size != new_r.addr_range.size)
                    {
                        if !is_add {
                            self.call_listeners(Some(old_r), None, ListenerReqType::DeleteRegion)?;
                        }
                        old_idx += 1;
                        continue;
                    }
                } else {
                    if !is_add {
                        self.call_listeners(Some(old_r), None, ListenerReqType::DeleteRegion)?;
                    }
                    old_idx += 1;
                    continue;
                }
            }

            // current old_range is None, or current new_range is before old_range
            if is_add && new_range.is_some() {
                self.call_listeners(new_range, None, ListenerReqType::AddRegion)?;
            }
            new_idx += 1;
        }

        Ok(())
    }

    /// Updates ioeventfds pass according to New `RegionIoEventFd` array.
    ///
    /// # Arguments
    ///
    /// * `new_evtfds` - New `RegionIoEventFd` array.
    fn update_ioeventfds_pass(&self, new_evtfds: &[RegionIoEventFd]) -> Result<()> {
        let old_evtfds = self.ioeventfds.lock().unwrap();
        let mut old_idx = 0;
        let mut new_idx = 0;

        while old_idx < old_evtfds.len() || new_idx < new_evtfds.len() {
            let old_fd = old_evtfds.get(old_idx);
            let new_fd = new_evtfds.get(new_idx);
            if old_fd.is_some() && (new_fd.is_none() || old_fd.unwrap().before(new_fd.unwrap())) {
                self.call_listeners(None, old_fd, ListenerReqType::DeleteIoeventfd)?;
                old_idx += 1;
            } else if new_fd.is_some()
                && (old_fd.is_none() || new_fd.unwrap().before(old_fd.unwrap()))
            {
                self.call_listeners(None, new_fd, ListenerReqType::AddIoeventfd)?;
                new_idx += 1;
            } else {
                old_idx += 1;
                new_idx += 1;
            }
        }

        Ok(())
    }

    /// Update IoEvents.
    fn update_ioeventfds(&self) -> Result<()> {
        let flatview = self.flat_view.read().unwrap();
        let mut ioeventfds = Vec::<RegionIoEventFd>::new();

        for fr in flatview.0.iter() {
            for evtfd in fr.owner.ioeventfds().iter() {
                if fr.addr_range.find_intersection(evtfd.addr_range).is_some() {
                    ioeventfds.push(evtfd.try_clone()?);
                }
            }
        }

        self.update_ioeventfds_pass(&ioeventfds)?;
        *self.ioeventfds.lock().unwrap() = ioeventfds;
        Ok(())
    }

    /// Return the start host address of Region where the `GuestAddress` belongs to.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address.
    pub fn get_host_address(&self, addr: GuestAddress) -> Option<u64> {
        let view = &self.flat_view.read().unwrap().0;

        match view.binary_search_by_key(&addr, |x| x.addr_range.base) {
            Ok(x) => view[x]
                .owner
                .get_host_address()
                .map(|hva| hva + view[x].offset_in_region),
            Err(x) if (x > 0 && addr < view[x - 1].addr_range.end_addr()) => {
                let offset = addr.offset_from(view[x - 1].addr_range.base);
                let offset_in_region = view[x - 1].offset_in_region;
                view[x - 1]
                    .owner
                    .get_host_address()
                    .map(|hva| hva + offset_in_region + offset)
            }
            _ => None,
        }
    }

    /// Check if the GuestAddress is in one of Ram region.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address.
    pub fn address_in_memory(&self, addr: GuestAddress, size: u64) -> bool {
        let view = &self.flat_view.read().unwrap().0;

        match view.binary_search_by_key(&addr, |x| x.addr_range.base) {
            Ok(x) => {
                view[x].owner.region_type() == RegionType::Ram && size <= view[x].addr_range.size
            }
            Err(x) if (x > 0 && addr < view[x - 1].addr_range.end_addr()) => {
                view[x - 1].owner.region_type() == RegionType::Ram
                    && size <= view[x - 1].addr_range.end_addr().offset_from(addr)
            }
            _ => false,
        }
    }

    /// Return the biggest end address in all Ram regions in AddressSpace.
    pub fn memory_end_address(&self) -> GuestAddress {
        let view = &self.flat_view.read().unwrap().0;
        view.iter()
            .filter(|fr| fr.owner.region_type() == RegionType::Ram)
            .max_by_key(|fr| fr.addr_range.end_addr())
            .map_or(GuestAddress(0), |fr| fr.addr_range.end_addr())
    }

    /// Read memory segment to `dst`.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination the data would be written to.
    /// * `addr` - Start address.
    /// * `count` - Size of data.
    ///
    /// # Errors
    ///
    /// Return Error if the `addr` is a invalid GuestAddress.
    pub fn read(&self, dst: &mut dyn std::io::Write, addr: GuestAddress, count: u64) -> Result<()> {
        let view = &self.flat_view.read().unwrap().0;

        let (fr, offset) = match view.binary_search_by_key(&addr, |x| x.addr_range.base) {
            Ok(x) => (&view[x], 0),
            Err(x) if (x > 0 && addr < view[x - 1].addr_range.end_addr()) => {
                let fr = &view[x - 1];
                (fr, addr.offset_from(fr.addr_range.base))
            }
            _ => return Err(ErrorKind::AddrInvalid(addr.raw_value()).into()),
        };

        fr.owner.read(
            dst,
            fr.addr_range.base.unchecked_sub(fr.offset_in_region),
            fr.offset_in_region + offset,
            count,
        )
    }

    /// Write memory segment to `dst`.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination the data would be written to.
    /// * `addr` - Start address.
    /// * `count` - Size of data.
    ///
    /// # Errors
    ///
    /// Return Error if the `addr` is a invalid GuestAddress.
    pub fn write(&self, src: &mut dyn std::io::Read, addr: GuestAddress, count: u64) -> Result<()> {
        let view = &self.flat_view.read().unwrap().0;

        let (fr, offset) = match view.binary_search_by_key(&addr, |x| x.addr_range.base) {
            Ok(x) => (&view[x], 0),
            Err(x) if (x > 0 && addr < view[x - 1].addr_range.end_addr()) => {
                let fr = &view[x - 1];
                (fr, addr.offset_from(fr.addr_range.base))
            }
            _ => return Err(ErrorKind::AddrInvalid(addr.raw_value()).into()),
        };

        fr.owner.write(
            src,
            fr.addr_range.base.unchecked_sub(fr.offset_in_region),
            fr.offset_in_region + offset,
            count,
        )
    }

    /// Write an object to memory.
    ///
    /// # Arguments
    ///
    /// * `data` - The object that will be written to the memory.
    /// * `addr` - The start address of memory where the object will be written to.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn write_object<T: ByteCode>(&self, data: &T, addr: GuestAddress) -> Result<()> {
        self.write(&mut data.as_bytes(), addr, std::mem::size_of::<T>() as u64)
    }

    /// Read some data from memory to form an object.
    ///
    /// # Arguments
    ///
    /// * `addr` - The start address of memory where the data will be read from.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn read_object<T: ByteCode>(&self, addr: GuestAddress) -> Result<T> {
        let mut obj = T::default();
        self.read(
            &mut obj.as_mut_bytes(),
            addr,
            std::mem::size_of::<T>() as u64,
        )?;
        Ok(obj)
    }

    /// Update the topology of memory.
    pub fn update_topology(&self) -> Result<()> {
        let old_fv = self.flat_view.read().unwrap();

        let addr_range = AddressRange::new(GuestAddress(0), self.root.size());
        let new_fv = self.root.generate_flatview(GuestAddress(0), addr_range)?;

        self.update_topology_pass(&old_fv, &new_fv, false)?;
        self.update_topology_pass(&old_fv, &new_fv, true)?;

        drop(old_fv);
        *self.flat_view.write().unwrap() = new_fv;
        self.update_ioeventfds()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::{HostMemMapping, RegionOps};

    #[derive(Default, Clone)]
    struct TestListener {
        reqs: Arc<Mutex<Vec<(ListenerReqType, AddressRange)>>>,
    }

    impl Listener for TestListener {
        fn priority(&self) -> i32 {
            2
        }

        fn handle_request(
            &self,
            range: Option<&FlatRange>,
            eventfd: Option<&RegionIoEventFd>,
            req_type: ListenerReqType,
        ) -> Result<()> {
            match req_type {
                ListenerReqType::AddRegion | ListenerReqType::DeleteRegion => {
                    self.reqs
                        .lock()
                        .unwrap()
                        .push((req_type, range.unwrap().addr_range));
                }
                ListenerReqType::AddIoeventfd | ListenerReqType::DeleteIoeventfd => {
                    self.reqs
                        .lock()
                        .unwrap()
                        .push((req_type, eventfd.unwrap().addr_range));
                }
            }
            Ok(())
        }
    }

    struct TestDevice;
    impl RegionOps for TestDevice {
        fn read(&mut self, _data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
            true
        }

        fn write(&mut self, _data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
            true
        }
    }

    // the listeners in AddressSpace is settled in ascending order by priority
    #[test]
    fn test_listeners() {
        // define an array of listeners in order to check the priority order
        struct ListenerPrior0;
        impl Listener for ListenerPrior0 {
            fn priority(&self) -> i32 {
                0
            }
        }
        struct ListenerPrior3;
        impl Listener for ListenerPrior3 {
            fn priority(&self) -> i32 {
                3
            }
        }
        struct ListenerPrior4;
        impl Listener for ListenerPrior4 {
            fn priority(&self) -> i32 {
                4
            }
        }
        struct ListenerNeg;
        impl Listener for ListenerNeg {
            fn priority(&self) -> i32 {
                -1
            }
        }

        let root = Region::init_container_region(8000);
        let space = AddressSpace::new(root).unwrap();
        let listener1 = Box::new(ListenerPrior0);
        let listener2 = Box::new(ListenerPrior0);
        let listener3 = Box::new(ListenerPrior3);
        let listener4 = Box::new(ListenerPrior4);
        let listener5 = Box::new(ListenerNeg);
        space.register_listener(listener1).unwrap();
        space.register_listener(listener3).unwrap();
        space.register_listener(listener5).unwrap();
        space.register_listener(listener2).unwrap();
        space.register_listener(listener4).unwrap();

        let mut pre_prior = std::i32::MIN;
        for listener in space.listeners.lock().unwrap().iter() {
            let curr = listener.priority();
            assert!(pre_prior <= curr);
            pre_prior = curr;
        }
    }

    #[test]
    fn test_update_topology() {
        let root = Region::init_container_region(8000);
        let space = AddressSpace::new(root.clone()).unwrap();
        let listener = TestListener::default();
        space.register_listener(Box::new(listener.clone())).unwrap();

        // memory region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  C:    [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
        //  B:                  [                           ]
        //
        // the flat_view is as follows, region-b is container which will not appear in the flat-view
        //        [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
        let region_b = Region::init_container_region(4000);
        let region_c = Region::init_io_region(6000, Arc::new(Mutex::new(TestDevice)));
        region_b.set_priority(2);
        region_c.set_priority(1);
        root.add_subregion(region_b.clone(), 2000).unwrap();
        root.add_subregion(region_c.clone(), 0).unwrap();

        assert_eq!(space.flat_view.read().unwrap().0.len(), 1);
        assert_eq!(listener.reqs.lock().unwrap().len(), 1);
        assert_eq!(
            listener.reqs.lock().unwrap().get(0).unwrap().1,
            AddressRange::new(region_c.offset(), region_c.size())
        );
        listener.reqs.lock().unwrap().clear();

        // region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  C:    [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
        //  B:                  [                           ]
        //  D:                  [DDDDDD]
        // the flat_view is as follows,
        //        [CCCCCCCCCCCC][DDDDDD][CCCCCCCCCCCCCCCCCCC]
        let region_d = Region::init_io_region(1000, Arc::new(Mutex::new(TestDevice)));
        region_b.add_subregion(region_d.clone(), 0).unwrap();

        assert_eq!(space.flat_view.read().unwrap().0.len(), 3);
        assert_eq!(listener.reqs.lock().unwrap().len(), 4);
        // delete flat-range 0~6000 first, belonging to region_c
        assert_eq!(
            listener.reqs.lock().unwrap().get(0).unwrap().1,
            AddressRange::new(region_c.offset(), region_c.size())
        );
        // add range 0~2000, belonging to region_c
        assert_eq!(
            listener.reqs.lock().unwrap().get(1).unwrap().1,
            AddressRange::new(region_c.offset(), 2000)
        );
        // add range 2000~3000, belonging to region_d
        let region_d_range = AddressRange::new(GuestAddress(2000), region_d.size());
        assert_eq!(
            listener.reqs.lock().unwrap().get(2).unwrap().1,
            region_d_range
        );
        // add range 3000~6000, belonging to region_c
        assert_eq!(
            listener.reqs.lock().unwrap().get(3).unwrap().1,
            AddressRange::from((3000, 3000))
        );
    }

    #[test]
    fn test_update_ioeventfd() {
        struct TestIoEventFd;
        impl RegionOps for TestIoEventFd {
            fn read(&mut self, _data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
                true
            }

            fn write(&mut self, _data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
                true
            }

            fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
                vec![RegionIoEventFd {
                    fd: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                    addr_range: AddressRange::from((0, 4)),
                    data_match: true,
                    data: 0_64,
                }]
            }
        }

        // region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  b:           [BBBBBBBBBBBBB]
        //  c:                  [CCCCCCCCCCCCC]
        // the flat_view is as follows,
        //               [BBBBBBBBBBBBB][CCCCC]
        let root = Region::init_container_region(8000);
        let space = AddressSpace::new(root.clone()).unwrap();
        let listener = TestListener::default();
        space.register_listener(Box::new(listener.clone())).unwrap();

        let region_b = Region::init_io_region(2000, Arc::new(Mutex::new(TestIoEventFd)));
        region_b.set_priority(1);
        let region_c = Region::init_io_region(2000, Arc::new(Mutex::new(TestIoEventFd)));

        root.add_subregion(region_c, 2000).unwrap();
        assert_eq!(listener.reqs.lock().unwrap().len(), 2);
        assert_eq!(
            listener.reqs.lock().unwrap().get(1).unwrap().1,
            AddressRange::new(GuestAddress(2000), 4)
        );
        listener.reqs.lock().unwrap().clear();

        root.add_subregion(region_b, 1000).unwrap();
        assert_eq!(listener.reqs.lock().unwrap().len(), 5);
        // add ioeventfd of region_b
        assert_eq!(
            listener.reqs.lock().unwrap().get(3).unwrap().1,
            AddressRange::new(GuestAddress(1000), 4)
        );
        // ioeventfd in region_c is shawdowed, delete it
        assert_eq!(
            listener.reqs.lock().unwrap().get(4).unwrap().1,
            AddressRange::new(GuestAddress(2000), 4)
        );
    }

    #[test]
    fn test_get_ram_info() {
        let root = Region::init_container_region(8000);
        let space = AddressSpace::new(root.clone()).unwrap();

        let ram1 = Arc::new(HostMemMapping::new(GuestAddress(0), 1000, false).unwrap());
        let ram2 = Arc::new(HostMemMapping::new(GuestAddress(2000), 1000, false).unwrap());
        let region_a = Region::init_ram_region(ram1.clone());
        let region_b = Region::init_ram_region(ram2.clone());
        root.add_subregion(region_a, ram1.start_address().raw_value())
            .unwrap();
        root.add_subregion(region_b, ram2.start_address().raw_value())
            .unwrap();

        assert_eq!(
            space.memory_end_address(),
            ram2.start_address().unchecked_add(ram2.size())
        );
        assert!(space.address_in_memory(GuestAddress(0), 0));
        assert_eq!(space.address_in_memory(GuestAddress(1000), 0), false);
        assert_eq!(space.address_in_memory(GuestAddress(1500), 0), false);
        assert!(space.address_in_memory(GuestAddress(2900), 0));

        assert_eq!(
            space.get_host_address(GuestAddress(500)),
            Some(ram1.host_address() + 500)
        );
        assert_eq!(
            space.get_host_address(GuestAddress(2500)),
            Some(ram2.host_address() + 500)
        );

        // region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  a:    [AAAAAA]
        //  b:                  [BBBBBB]
        //  c:            [CCCCCCCCC]
        // the flat_view is as follows,
        //        [AAAAAA][CCCCCCCCC][BB]
        let region_c = Region::init_io_region(1500, Arc::new(Mutex::new(TestDevice)));
        region_c.set_priority(1);
        root.add_subregion(region_c, 1000).unwrap();

        assert_eq!(
            space.memory_end_address(),
            ram2.start_address().unchecked_add(ram2.size())
        );
        assert!(space.address_in_memory(GuestAddress(0), 0));
        assert_eq!(space.address_in_memory(GuestAddress(1000), 0), false);
        assert_eq!(space.address_in_memory(GuestAddress(1500), 0), false);
        assert_eq!(space.address_in_memory(GuestAddress(2400), 0), false);
        assert!(space.address_in_memory(GuestAddress(2900), 0));

        assert_eq!(
            space.get_host_address(GuestAddress(500)),
            Some(ram1.host_address() + 500)
        );
        assert!(space.get_host_address(GuestAddress(2400)).is_none());
        assert_eq!(
            space.get_host_address(GuestAddress(2500)),
            Some(ram2.host_address() + 500)
        );
    }

    #[test]
    fn test_write_and_read_object() {
        let root = Region::init_container_region(8000);
        let space = AddressSpace::new(root.clone()).unwrap();
        let ram1 = Arc::new(HostMemMapping::new(GuestAddress(0), 1000, false).unwrap());
        let region_a = Region::init_ram_region(ram1.clone());
        root.add_subregion(region_a, ram1.start_address().raw_value())
            .unwrap();

        let data: u64 = 10000;
        assert!(space.write_object(&data, GuestAddress(992)).is_ok());
        let data1: u64 = space.read_object(GuestAddress(992)).unwrap();
        assert_eq!(data1, 10000);
        assert!(space.write_object(&data, GuestAddress(993)).is_err());
    }
}
