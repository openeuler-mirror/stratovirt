# 构建测试镜像

1. 请于openEuler官网，下载所需版本的stratovirt_img和vmlinux.bin。(以下以openEuler-21.03-stratovirt-x86_64.img为例)

- 地址：https://openeuler.org/zh/download/

2. 扩容镜像

- 创建一个2G大小的空镜像文件extend.img

	```shell
	dd if=/dev/zero of=extend.img bs=50M count=40
	```

- 扩容stratovirt_img

	```shell
	cat extend.img >> openEuler-21.03-stratovirt-x86_64.img
	```

- 调整文件系统大小

	```shell
	e2fsck -f openEuler-21.03-stratovirt-x86_64.img && resize2fs openEuler-21.03-stratovirt-x86_64.img
	```

3. 添加依赖包

- 挂载镜像

	```shell
	mount openEuler-21.03-stratovirt-x86_64.img /mnt
	```

- 配置在线yum源，请参考： [开发环境准备.md](https://gitee.com/openeuler/docs/blob/stable2-21.03/docs/zh/docs/ApplicationDev/开发环境准备.md)。由于stratovirt_img内没有vi等编辑工具，建议先在主机上创建文件openEuler.repo，并配置好yum源，完成后将openEuler.repo拷贝到镜像内。

	```shell
	cp ./openEuler.repo /mnt/etc/yum.repos.d
	```

- 进入镜像挂载目录，通过yum命令安装依赖包。

	```shell
	cd /mnt
	chroot .
	yum -y install openSSH
	```

- 离开当前目录后，使用umount命令卸载镜像。

	```shell
	exit
	umount /mnt
	```
