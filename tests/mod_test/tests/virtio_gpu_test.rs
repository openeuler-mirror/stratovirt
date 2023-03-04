// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use mod_test::libdriver::virtio_gpu::{
    current_curosr_check, current_surface_check, get_display_info, get_edid, invalid_cmd_test,
    resource_attach_backing, resource_attach_backing_with_invalid_ctx_len, resource_create,
    resource_detach_backing, resource_flush, resource_unref, set_scanout, transfer_to_host,
    update_cursor, GpuDevConfig, VirtioGpuCtrlHdr, VirtioGpuDisplayInfo, VirtioGpuGetEdid,
    VirtioGpuMemEntry, VirtioGpuRect, VirtioGpuResourceAttachBacking, VirtioGpuResourceCreate2d,
    VirtioGpuResourceDetachBacking, VirtioGpuResourceFlush, VirtioGpuResourceUnref,
    VirtioGpuSetScanout, VirtioGpuTransferToHost2d,
};
use mod_test::libdriver::virtio_gpu::{set_up, tear_down};
use std::vec;
use util::byte_code::ByteCode;
use virtio::{
    get_image_hostmem, get_pixman_format, VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, VIRTIO_GPU_FORMAT_INVALID_UNORM,
    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID, VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
    VIRTIO_GPU_RESP_ERR_UNSPEC, VIRTIO_GPU_RESP_OK_DISPLAY_INFO, VIRTIO_GPU_RESP_OK_EDID,
    VIRTIO_GPU_RESP_OK_NODATA,
};

const D_RES_ID: u32 = 1;
const D_SCANOUT_ID: u32 = 0;
const D_INVALID_SCANOUT_ID: u32 = 100;
const D_FMT: u32 = 2;
const D_INVALD_FMT: u32 = VIRTIO_GPU_FORMAT_INVALID_UNORM;
const D_WIDTH: u32 = 64;
const D_HEIGHT: u32 = 64;
const D_BYTE_PER_PIXEL: u32 = 4;
const D_IMG_SIZE: u32 = D_WIDTH * D_HEIGHT * D_BYTE_PER_PIXEL;
const D_OFFSET: u64 = 0;
const D_X_COORD: u32 = 0;
const D_Y_COORD: u32 = 0;
const D_INVALD_NR_ENTRIES: u32 = 1 + 16384;

#[test]
fn image_display_fun() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    let image_addr = gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    let image_byte_0 = vec![0 as u8; 1];
    let image_byte_1 = vec![1 as u8; 1];
    let image_0 = vec![0 as u8; image_size as usize];

    // image with half data 1
    let mut image_half_1 = vec![0 as u8; image_size as usize];
    let mut i = 0;
    while i < image_size / 2 {
        image_half_1[i as usize] = 1;
        i += 1;
    }
    // image with quarter data1
    let mut image_quarter_1 = vec![0 as u8; image_size as usize];
    let mut i = 0;
    while i < image_size / 4 {
        image_quarter_1[i as usize] = 1;
        i += 1;
    }

    assert_eq!(
        VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
        get_display_info(&gpu).header.hdr_type
    );

    assert_eq!(
        VIRTIO_GPU_RESP_OK_EDID,
        get_edid(&gpu, VirtioGpuGetEdid::new(D_SCANOUT_ID))
            .header
            .hdr_type
    );

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    gpu.borrow_mut()
        .state
        .borrow_mut()
        .memset(image_addr, image_size, &image_byte_0);

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_attach_backing(
            &gpu,
            VirtioGpuResourceAttachBacking::new(D_RES_ID, 1),
            vec![VirtioGpuMemEntry::new(image_addr, image_size as u32)]
        )
        .hdr_type
    );

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        transfer_to_host(
            &gpu,
            VirtioGpuTransferToHost2d::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_OFFSET,
                D_RES_ID,
            ),
        )
        .hdr_type
    );

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        set_scanout(
            &gpu,
            VirtioGpuSetScanout::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_SCANOUT_ID,
                D_RES_ID,
            )
        )
        .hdr_type
    );
    assert!(current_surface_check(&dpy, &image_0));

    // update image, half of image change to 1
    gpu.borrow_mut()
        .state
        .borrow_mut()
        .memset(image_addr, image_size / 2, &image_byte_1);

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        transfer_to_host(
            &gpu,
            VirtioGpuTransferToHost2d::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_OFFSET,
                D_RES_ID,
            ),
        )
        .hdr_type
    );

    // But we only flush quarter of the image. So check the image is quarter 1 or not.
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_flush(
            &gpu,
            VirtioGpuResourceFlush::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT / 4),
                D_RES_ID
            )
        )
        .hdr_type
    );
    assert!(current_surface_check(&dpy, &image_quarter_1));

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_detach_backing(&gpu, VirtioGpuResourceDetachBacking::new(D_RES_ID),).hdr_type
    );

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_unref(&gpu, VirtioGpuResourceUnref::new(D_RES_ID)).hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn cursor_display_fun() {
    let image_0: Vec<u8> = vec![0 as u8; D_IMG_SIZE as usize];
    let image_1: Vec<u8> = vec![1 as u8; D_IMG_SIZE as usize];
    let image_byte_1 = vec![1 as u8; 1];

    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);

    let image_addr = gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // init data is all 0
    update_cursor(&gpu, D_RES_ID, D_SCANOUT_ID);
    assert!(current_curosr_check(&dpy, &image_0));

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_attach_backing(
            &gpu,
            VirtioGpuResourceAttachBacking::new(D_RES_ID, 1),
            vec![VirtioGpuMemEntry::new(image_addr, image_size as u32)]
        )
        .hdr_type
    );

    // update image to 1
    gpu.borrow_mut()
        .state
        .borrow_mut()
        .memset(image_addr, image_size, &image_byte_1);

    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        transfer_to_host(
            &gpu,
            VirtioGpuTransferToHost2d::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_OFFSET,
                D_RES_ID,
            ),
        )
        .hdr_type
    );

    // now resource data is all 1
    update_cursor(&gpu, D_RES_ID, D_SCANOUT_ID);
    assert!(current_curosr_check(&dpy, &image_1));

    tear_down(dpy, gpu);
}

#[test]
fn resource_create_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);

    // exceed max_hostmem
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH + 1, D_HEIGHT)
        )
        .hdr_type
    );

    // invalid format
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_INVALD_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // invalid resource id 0
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(0, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // resource id exist
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT / 2)
        )
        .hdr_type
    );
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT / 2)
        )
        .hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn resource_destroy_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);
    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;
    let (dpy, gpu) = set_up(&gpu_cfg);

    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        resource_unref(&gpu, VirtioGpuResourceUnref::new(D_RES_ID)).hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn resource_attach_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    let image_addr = gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    // resource is invalid yet
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        resource_attach_backing(
            &gpu,
            VirtioGpuResourceAttachBacking::new(D_RES_ID, 1),
            vec![VirtioGpuMemEntry::new(image_addr, image_size as u32)]
        )
        .hdr_type
    );

    // create resource first
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // invalid nr_entries
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_UNSPEC,
        resource_attach_backing(
            &gpu,
            VirtioGpuResourceAttachBacking::new(D_RES_ID, D_INVALD_NR_ENTRIES),
            vec![VirtioGpuMemEntry::new(image_addr, image_size as u32)]
        )
        .hdr_type
    );

    // invalid context length
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_UNSPEC,
        resource_attach_backing_with_invalid_ctx_len(
            &gpu,
            VirtioGpuResourceAttachBacking::new(D_RES_ID, 1)
        )
        .hdr_type
    );

    // invalid context address
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_UNSPEC,
        resource_attach_backing(
            &gpu,
            VirtioGpuResourceAttachBacking::new(D_RES_ID, 1),
            vec![VirtioGpuMemEntry::new(0, image_size as u32)]
        )
        .hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn resource_detach_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    // invlid resource id
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        resource_detach_backing(&gpu, VirtioGpuResourceDetachBacking::new(D_RES_ID),).hdr_type
    );

    // create resource first
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // invlid resource id
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_UNSPEC,
        resource_detach_backing(&gpu, VirtioGpuResourceDetachBacking::new(D_RES_ID),).hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn resource_transfer_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    let image_addr = gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    // invlid resource id
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        transfer_to_host(
            &gpu,
            VirtioGpuTransferToHost2d::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_OFFSET,
                D_RES_ID,
            ),
        )
        .hdr_type
    );

    // create resource first
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // have not attach any data source
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        transfer_to_host(
            &gpu,
            VirtioGpuTransferToHost2d::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_OFFSET,
                D_RES_ID,
            ),
        )
        .hdr_type
    );

    // attach first
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_attach_backing(
            &gpu,
            VirtioGpuResourceAttachBacking::new(D_RES_ID, 1),
            vec![VirtioGpuMemEntry::new(image_addr, image_size as u32)]
        )
        .hdr_type
    );

    // invalid rect region
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
        transfer_to_host(
            &gpu,
            VirtioGpuTransferToHost2d::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH + 1, D_HEIGHT - 1),
                D_OFFSET,
                D_RES_ID,
            ),
        )
        .hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn scanout_set_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    // invalid scanout id
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
        set_scanout(
            &gpu,
            VirtioGpuSetScanout::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_INVALID_SCANOUT_ID,
                D_RES_ID,
            )
        )
        .hdr_type
    );

    // invalid resource id
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        set_scanout(
            &gpu,
            VirtioGpuSetScanout::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_SCANOUT_ID,
                D_RES_ID,
            )
        )
        .hdr_type
    );

    // create resource first
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // invalid rect region
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
        set_scanout(
            &gpu,
            VirtioGpuSetScanout::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH + 1, D_HEIGHT),
                D_SCANOUT_ID,
                D_RES_ID,
            )
        )
        .hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn scanout_flush_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    // invalid resource id
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
        resource_flush(
            &gpu,
            VirtioGpuResourceFlush::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH, D_HEIGHT),
                D_RES_ID
            )
        )
        .hdr_type
    );

    // create resource first
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT)
        )
        .hdr_type
    );

    // invalid rect region
    assert_eq!(
        VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
        resource_flush(
            &gpu,
            VirtioGpuResourceFlush::new(
                VirtioGpuRect::new(D_X_COORD, D_Y_COORD, D_WIDTH + 1, D_HEIGHT),
                D_RES_ID
            )
        )
        .hdr_type
    );

    tear_down(dpy, gpu);
}

#[test]
fn cursor_update_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    let image_empty: Vec<u8> = vec![];
    let image_0: Vec<u8> = vec![0 as u8; D_IMG_SIZE as usize];

    // invalid scanout id
    assert!(current_curosr_check(&dpy, &image_empty));
    update_cursor(&gpu, D_RES_ID, D_INVALID_SCANOUT_ID);
    assert!(current_curosr_check(&dpy, &image_empty));

    // invalid resource id
    update_cursor(&gpu, D_RES_ID, D_SCANOUT_ID);
    assert!(current_curosr_check(&dpy, &image_0));

    // create resource which have invalid width
    assert_eq!(
        VIRTIO_GPU_RESP_OK_NODATA,
        resource_create(
            &gpu,
            VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH / 2, D_HEIGHT)
        )
        .hdr_type
    );
    // invalid rect region even resource is exist
    update_cursor(&gpu, D_RES_ID, D_SCANOUT_ID);
    assert!(current_curosr_check(&dpy, &image_0));

    tear_down(dpy, gpu);
}

#[test]
fn invalid_cmd_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    // invalid cmd
    assert_eq!(VIRTIO_GPU_RESP_ERR_UNSPEC, invalid_cmd_test(&gpu).hdr_type);

    tear_down(dpy, gpu);
}

#[test]
fn crash_dfx() {
    let pixman_format = get_pixman_format(D_FMT).unwrap();
    let image_size = get_image_hostmem(pixman_format, D_WIDTH, D_HEIGHT);

    let mut gpu_cfg = GpuDevConfig::default();
    gpu_cfg.max_hostmem = image_size;

    let (dpy, gpu) = set_up(&gpu_cfg);
    gpu.borrow_mut().allocator.borrow_mut().alloc(image_size);

    // invalid request header length
    let mut hdr = VirtioGpuCtrlHdr::default();
    hdr.hdr_type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;

    let mut resp = VirtioGpuDisplayInfo::default();
    resp.header.hdr_type = 0x1234; // will not change because req has been ignored

    let temp = hdr.as_bytes();
    let slice = &temp[4..];
    gpu.borrow_mut()
        .request_complete(true, slice, None, None, Some(&mut resp));
    assert_eq!(0x1234, resp.header.hdr_type);

    // invlid hdr_ctx
    let mut hdr = VirtioGpuCtrlHdr::default();
    hdr.hdr_type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;

    let hdr_ctx = VirtioGpuResourceCreate2d::new(D_RES_ID, D_FMT, D_WIDTH, D_HEIGHT);

    let mut resp = VirtioGpuCtrlHdr::default();

    let temp = hdr_ctx.as_bytes();
    let slice = &temp[4..];

    gpu.borrow_mut()
        .request_complete(true, hdr.as_bytes(), Some(slice), None, Some(&mut resp));
    assert_eq!(VIRTIO_GPU_RESP_ERR_UNSPEC, resp.hdr_type);

    tear_down(dpy, gpu);
}
