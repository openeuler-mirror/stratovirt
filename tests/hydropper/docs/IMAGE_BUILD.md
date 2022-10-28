# 构建测试镜像

1. 请于openEuler官网，下载所需版本的stratovirt_img。(以下以openEuler-22.03-LTS-stratovirt-x86_64.img为例)

- 地址：https://openeuler.org/zh/download/

2. 扩容镜像

- 创建一个2G大小的空镜像文件extend.img

	```shell
	dd if=/dev/zero of=extend.img bs=50M count=40
	```

- 扩容stratovirt_img

	```shell
	cat extend.img >> openEuler-22.03-LTS-stratovirt-x86_64.img
	```

- 调整文件系统大小

	```shell
	e2fsck -f openEuler-22.03-LTS-stratovirt-x86_64.img && resize2fs openEuler-22.03-LTS-stratovirt-x86_64.img
	```

3. 添加依赖包

- 挂载镜像

	```shell
	mount openEuler-22.03-LTS-stratovirt-x86_64.img /mnt
	```

- 配置DNS服务配置文件(/etc/resolv.conf)。挂载镜像中的etc/resolv.conf文件为空，需要配置DNS服务才能更新yum源。

	```shell
	cp /etc/resolv.conf /mnt/etc/resolv.conf
	```

- 进入镜像挂载目录，通过yum命令安装依赖包。

	```shell
	cd /mnt
	chroot .
	echo "set enable-bracketed-paste off"  > /root/.inputrc
	yum -y install openssh
	# For PMU tests
	yum -y install perf
	```

- 离开当前目录后，使用umount命令卸载镜像。

	```shell
	exit
	umount /mnt
	```
