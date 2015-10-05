“待月西厢下，迎风户半开，隔墙花影动，疑是玉人来。”

West-chamber is a research project for the detection and circumvention against
hostile intrusion detection and disruption, especially the Great Firewall of
China.

西厢计划是一个对敌对入侵检测和干扰行为进行检测和规避的研究计划。主要的研究对象是GFW。

西厢计划的项目组成：

  * trunk/west-chamber - 基于netfilter/xtables的内核模块：Klzgrad和yingyingcui
  * trunk/west-chamber-windows - Windows移植：Elysion，fuyuchen945，MxSiyuan。
  * branches/scholarzhang-0.3.2 - ZHANG的用户态实现（libpcap/winpcap）：Klzgrad。
  * branches/yingyingcui-0.3.2 - CUI的用户态实现：yingyingcui。
  * trunk/keywords - 关键词自动检测工具：
  * 代码维护：tewilove，liruqi。
  * 文档：Klzgrad。
  * Gentoo打包：zhixun.lin。
  * RPM打包：Caius 'kaio' Chance。

也介绍一些本项目启发出的新项目：

  * [liujinyuan](https://github.com/tewilove/liujinyuan)：tewilove开发的Android分支/移植。
  * [西厢计划第二季](http://code.google.com/p/west-chamber-season-2/)：单向隧道。
  * [西厢计划第三季](http://code.google.com/p/west-chamber-season-3/)：liruqi等对西厢的继续开发。
  * [kernet](https://github.com/ccp0101/kernet)：“西厢的Mac移植版”，ccp0101开发。

西厢计划发布于GPLv2+。文档：[README (中文)](http://code.google.com/p/scholarzhang/wiki/README)，[README (English)](https://scholarzhang.googlecode.com/svn/trunk/west-chamber/README.html)，[INSTALL (English)](https://scholarzhang.googlecode.com/svn/trunk/west-chamber/INSTALL.html)，[HOWTO (English)](https://scholarzhang.googlecode.com/svn/trunk/west-chamber/HOWTO.html)，[HOWTO (中文)](https://scholarzhang.googlecode.com/svn/trunk/west-chamber/HOWTO.zh.html)。

## News ##
  * 4/7 Windows版本更新了GFW指纹、加入了x64版本的支持。IA64未发布binary版，亦未进行测试。
  * 4/4 减弱了gfw判断条件。
  * 4/1下午4时左右, GFW改变type2指纹，-m gfw规则失效，其直接影响为linux下反DNS污染失效。
  * 3/16, kaio制作Fedora包，见http://code.google.com/p/scholarzhang/downloads/list
  * 3/15, Wiki文档授权[更新](http://code.google.com/p/scholarzhang/source/detail?r=56)为GFDL与CC-by-sa-3.0双许可证。
  * 3/15, CUI的用户态实现demo。
  * 3/15, windows移植alpha完成，trunk/west-chamber-windows。
  * 3/14, Archlinux的两个pkgbuild：[west-chamber](http://aur.archlinux.org/packages.php?ID=35391)和[west-chamber-svn](http://aur.archlinux.org/packages.php?ID=35407)。Gentoo的[ebuild](http://www.linuxsir.org/bbs/thread364811.html)，gentoo-china-overlay [r1176](http://code.google.com/p/gentoo-china-overlay/source/detail?r=1176)。
  * 3/11, 设立[开发邮件列表](https://groups.google.com/group/scholarzhang-dev)
  * 3/10, 0.0.1 初始版本